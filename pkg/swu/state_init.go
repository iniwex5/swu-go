package swu

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"errors"
	"fmt"

	"github.com/iniwex5/swu-go/pkg/crypto"
	"github.com/iniwex5/swu-go/pkg/ikev2"
	"github.com/iniwex5/swu-go/pkg/logger"
)

func classifyIKEProfile(encrID, integID, prfID uint16) string {
	switch {
	case prfID == uint16(ikev2.PRF_AES128_XCBC) || integID == uint16(ikev2.AUTH_AES_XCBC_96):
		return "xcbc_legacy"
	case prfID == uint16(ikev2.PRF_HMAC_SHA2_256) && integID == uint16(ikev2.AUTH_HMAC_SHA2_256_128):
		return "sha2_modern"
	case prfID == uint16(ikev2.PRF_HMAC_SHA1) && integID == uint16(ikev2.AUTH_HMAC_SHA1_96):
		return "sha1_legacy"
	default:
		return "mixed"
	}
}

func detectOutboundIPv4(remoteIP net.IP, remotePort uint16) (net.IP, error) {
	if remoteIP == nil {
		return nil, errors.New("remote ip is nil")
	}
	r := &net.UDPAddr{IP: remoteIP, Port: int(remotePort)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "udp", r.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if v4 := ua.IP.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, errors.New("cannot detect outbound ip")
}

func (s *Session) sendIKESAInit() error {
	data, err := s.buildIKESAInitPacket()
	if err != nil {
		return err
	}
	return s.socket.SendIKE(data)
}

func (s *Session) buildIKESAInitPacket() ([]byte, error) {
	if len(s.ni) == 0 {
		s.ni = make([]byte, 32)
		rand.Read(s.ni)
	}

	// 使用配置驱动的 IKE Proposal；为空时回退到内置大兼容集合。
	proposals, err := buildIKEProposals(s.cfg.IKEProposals, nil)
	if err != nil {
		return nil, err
	}

	if s.DH != nil {
		// 这是重试协商的情况（e.g. 处理了 INVALID_KE_PAYLOAD）
		// 我们必须确保 SA 载荷中包含我们实际使用的这个 DH Group
		found := false
		for _, p := range proposals {
			for _, t := range p.Transforms {
				if t.Type == ikev2.TransformTypeDH && t.ID == ikev2.AlgorithmType(s.DH.Group) {
					found = true
				}
			}
		}
		if !found {
			// 如果当前生成的所有 Proposal 中没有我们需要的 DH Group，
			// 将当前所有 Proposal 中的 DH 强制替换为服务器要求的新的 DH Group
			for _, p := range proposals {
				for _, t := range p.Transforms {
					if t.Type == ikev2.TransformTypeDH {
						t.ID = ikev2.AlgorithmType(s.DH.Group)
					}
				}
			}
		}
		prioritizeDHGroup(proposals, ikev2.AlgorithmType(s.DH.Group))
	} else {
		// 第一次发送，取 Proposal 里的首选 DH Group 为主
		dhGroup := firstDHGroupFromProposals(proposals)
		s.DH, err = crypto.NewDiffieHellman(uint16(dhGroup))
		if err != nil {
			return nil, err
		}
		if err := s.DH.GenerateKey(); err != nil {
			return nil, err
		}
	}

	saPayload := &ikev2.EncryptedPayloadSA{
		Proposals: proposals,
	}

	kePayload := &ikev2.EncryptedPayloadKE{
		DHGroup: ikev2.AlgorithmType(s.DH.Group), // 动态读取当前的 DH 组
		KEData:  s.DH.PublicKeyBytes(),
	}

	noncePayload := &ikev2.EncryptedPayloadNonce{
		NonceData: s.ni,
	}

	localPort := s.cfg.LocalPort
	if localPort == 0 {
		if lp, ok := s.socket.(interface{ LocalPort() uint16 }); ok {
			localPort = lp.LocalPort()
		}
	}
	remoteIP := net.ParseIP(s.cfg.EpDGAddr).To4()
	remotePort := s.cfg.EpDGPort
	if remotePort == 0 {
		remotePort = 500
	}

	if ep, ok := s.socket.(interface {
		LocalIP() net.IP
		RemoteIP() net.IP
		RemotePort() int
	}); ok {
		if rip := ep.RemoteIP(); rip != nil {
			if v4 := rip.To4(); v4 != nil {
				remoteIP = v4
			}
		}
		if rp := ep.RemotePort(); rp != 0 {
			remotePort = uint16(rp)
		}
	}

	localIP := net.ParseIP(s.cfg.LocalAddr).To4()
	if ep, ok := s.socket.(interface{ LocalIP() net.IP }); ok {
		if lip := ep.LocalIP(); lip != nil {
			if v4 := lip.To4(); v4 != nil && !v4.Equal(net.IPv4zero) {
				localIP = v4
			}
		}
	}
	if localIP == nil || localIP.Equal(net.IPv4zero) {
		if remoteIP != nil {
			if out, err := detectOutboundIPv4(remoteIP, remotePort); err == nil && out != nil {
				localIP = out
			}
		}
	}

	srcHash := ikev2.CalculateNATDetectionHash(s.SPIi, 0, localIP, localPort)
	natSrcPayload := ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_SOURCE_IP, srcHash)

	dstHash := ikev2.CalculateNATDetectionHash(s.SPIi, 0, remoteIP, remotePort)
	natDstPayload := ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_DESTINATION_IP, dstHash)

	// IKE Fragmentation (RFC 7383)
	// IKE_SA_INIT 必须携带此通知
	fragNotify := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.IKEV2_FRAGMENTATION_SUPPORTED,
	}

	// 顺序: [COOKIE], SA, KE, Nonce, FRAG, NAT_SRC, NAT_DST
	var payloads []ikev2.Payload

	// RFC 7296 §2.6: Cookie类型的通知有效负载必须是第一个有效负载
	if s.sendCookie && len(s.cookie) > 0 {
		payloads = append(payloads, &ikev2.EncryptedPayloadNotify{
			ProtocolID: 0,
			NotifyType: ikev2.COOKIE,
			NotifyData: s.cookie,
		})
	}

	payloads = append(payloads, saPayload, kePayload, noncePayload, fragNotify)
	payloads = append(payloads, natSrcPayload, natDstPayload)

	packet := ikev2.NewIKEPacket()
	packet.Header.SPIi = s.SPIi
	packet.Header.Version = 0x20
	packet.Header.ExchangeType = ikev2.IKE_SA_INIT
	packet.Header.Flags = ikev2.FlagInitiator
	packet.Header.MessageID = 0
	packet.Payloads = payloads

	data, err := packet.Encode()
	if err != nil {
		return nil, err
	}

	s.msgBuffer = data
	return data, nil
}

func prioritizeDHGroup(proposals []*ikev2.Proposal, preferred ikev2.AlgorithmType) {
	for _, p := range proposals {
		var dhs []*ikev2.Transform
		others := make([]*ikev2.Transform, 0, len(p.Transforms))
		for _, t := range p.Transforms {
			if t.Type == ikev2.TransformTypeDH {
				dhs = append(dhs, t)
				continue
			}
			others = append(others, t)
		}
		if len(dhs) == 0 {
			continue
		}

		orderedDHs := make([]*ikev2.Transform, 0, len(dhs))
		for _, t := range dhs {
			if t.ID == preferred {
				orderedDHs = append(orderedDHs, t)
			}
		}
		for _, t := range dhs {
			if t.ID != preferred {
				orderedDHs = append(orderedDHs, t)
			}
		}
		p.Transforms = append(others, orderedDHs...)
	}
}

func (s *Session) handleIKESAInitResp(data []byte) error {
	packet, err := ikev2.DecodePacket(data)
	if err != nil {
		return fmt.Errorf("解码 SA_INIT 响应失败: %v", err)
	}

	// 检查头部
	if packet.Header.ExchangeType != ikev2.IKE_SA_INIT {
		return fmt.Errorf("意外的交换类型: %d", packet.Header.ExchangeType)
	}
	s.SPIr = packet.Header.SPIr

	// 提取载荷
	var saPayload *ikev2.EncryptedPayloadSA
	var kePayload *ikev2.EncryptedPayloadKE
	var noncePayload *ikev2.EncryptedPayloadNonce
	var natSrc []byte
	var natDst []byte

	for _, p := range packet.Payloads {
		switch v := p.(type) {
		case *ikev2.EncryptedPayloadSA:
			saPayload = v
		case *ikev2.EncryptedPayloadKE:
			kePayload = v
		case *ikev2.EncryptedPayloadNonce:
			noncePayload = v
		case *ikev2.EncryptedPayloadNotify:
			if v.NotifyType == ikev2.COOKIE {
				if err := s.handleCookie(v.NotifyData); err != nil {
					return err
				}
				return ErrCookieRequired
			}
			if v.NotifyType == ikev2.NAT_DETECTION_SOURCE_IP {
				natSrc = v.NotifyData
			}
			if v.NotifyType == ikev2.NAT_DETECTION_DESTINATION_IP {
				natDst = v.NotifyData
			}
			// IKE Fragmentation (RFC 7383)
			if v.NotifyType == ikev2.IKEV2_FRAGMENTATION_SUPPORTED {
				s.fragmentationSupported = true
				s.Logger.Debug("ePDG 支持 IKE Fragmentation")
			}
			// 检查错误，如 NO_PROPOSAL_CHOSEN
			if v.NotifyType == 14 { // NO_PROPOSAL_CHOSEN
				return errors.New("服务器拒绝了提议 (NO_PROPOSAL_CHOSEN)")
			}
			// RFC 5685: REDIRECT
			if v.NotifyType == ikev2.REDIRECT {
				addr, err := ParseRedirectData(v.NotifyData)
				if err != nil {
					s.Logger.Warn("解析 REDIRECT 数据失败", logger.Err(err))
				} else {
					return &RedirectError{NewAddr: addr}
				}
				continue
			}

			// INVALID_KE_PAYLOAD (RFC 7296 §2.6.1): NotifyData 含 2 字节期望 DH Group ID
			if v.NotifyType == 17 { // INVALID_KE_PAYLOAD
				if len(v.NotifyData) >= 2 {
					preferredGroup := binary.BigEndian.Uint16(v.NotifyData[:2])
					return &ErrInvalidKEGroup{PreferredGroup: preferredGroup}
				}
				return errors.New("服务器拒绝 DH 群组 (INVALID_KE_PAYLOAD), 并未指定期望群组")
			}

			// RFC 7296: NotifyType < 16384 为错误类通知，直接中断协商
			if v.NotifyType < 16384 {
				return fmt.Errorf("服务器在 SA_INIT 阶段拒绝：%s (code=%d)", notifyTypeToString(v.NotifyType), v.NotifyType)
			}

			// 未知状态类 Notify（信息类，>= 16384）
			s.Logger.Debug("SA_INIT 收到状态类 Notify",
				logger.Int("type", int(v.NotifyType)),
				logger.Int("data_len", len(v.NotifyData)))
		}
	}

	if saPayload == nil || kePayload == nil || noncePayload == nil {
		return errors.New("SA_INIT 响应中缺少强制性载荷")
	}

	s.nr = noncePayload.NonceData

	if len(natSrc) > 0 && len(natDst) > 0 {
		localPort := s.cfg.LocalPort
		if localPort == 0 {
			if lp, ok := s.socket.(interface{ LocalPort() uint16 }); ok {
				localPort = lp.LocalPort()
			}
		}
		remoteIP := net.ParseIP(s.cfg.EpDGAddr).To4()
		remotePort := s.cfg.EpDGPort
		if remotePort == 0 {
			remotePort = 500
		}
		if ep, ok := s.socket.(interface {
			LocalIP() net.IP
			RemoteIP() net.IP
			RemotePort() int
		}); ok {
			if rip := ep.RemoteIP(); rip != nil {
				if v4 := rip.To4(); v4 != nil {
					remoteIP = v4
				}
			}
			if rp := ep.RemotePort(); rp != 0 {
				remotePort = uint16(rp)
			}
		}

		localIP := net.ParseIP(s.cfg.LocalAddr).To4()
		if ep, ok := s.socket.(interface{ LocalIP() net.IP }); ok {
			if lip := ep.LocalIP(); lip != nil {
				if v4 := lip.To4(); v4 != nil && !v4.Equal(net.IPv4zero) {
					localIP = v4
				}
			}
		}
		if localIP == nil || localIP.Equal(net.IPv4zero) {
			if remoteIP != nil {
				if out, err := detectOutboundIPv4(remoteIP, remotePort); err == nil && out != nil {
					localIP = out
				}
			}
		}

		expNatSrc := ikev2.CalculateNATDetectionHash(s.SPIi, s.SPIr, localIP, localPort)
		expNatDst := ikev2.CalculateNATDetectionHash(s.SPIi, s.SPIr, remoteIP, remotePort)

		natDetected := !bytes.Equal(natSrc, expNatSrc) || !bytes.Equal(natDst, expNatDst)
		if natDetected {
			if setter, ok := s.socket.(interface{ SetRemotePort(int) }); ok {
				setter.SetRemotePort(4500)
			}
			s.startNATKeepalive(20 * time.Second)
			s.Logger.Debug("检测到 NAT，切换到 UDP 4500")
		}
	}

	// 处理 SA 选择 (简化: 假设服务器接受了我们的提议)
	// 我们应该解析 `saPayload.Proposals[0]` 以查看选择了什么。
	// 获取转换。
	selProp := saPayload.Proposals[0]
	var prfID uint16
	var encrID uint16
	var encrKeyLenBits int
	var integID uint16
	var dhID uint16

	for _, t := range selProp.Transforms {
		switch t.Type {
		case ikev2.TransformTypeEncr:
			encrID = uint16(t.ID)
			for _, a := range t.Attributes {
				if a.Type == ikev2.AttributeKeyLength {
					encrKeyLenBits = int(a.Val)
				}
			}
		case ikev2.TransformTypeInteg:
			integID = uint16(t.ID)
		case ikev2.TransformTypePRF:
			prfID = uint16(t.ID)
		case ikev2.TransformTypeDH:
			dhID = uint16(t.ID)
		}
	}

	s.Logger.Debug("ePDG_SA_INIT: IKE SA 算法协商成功",
		logger.String("encr", ikev2.EncrToString(encrID)),
		logger.Int("encr_key_bits", encrKeyLenBits),
		logger.String("integ", ikev2.IntegToString(integID)),
		logger.String("prf", ikev2.PRFToString(prfID)),
		logger.String("dh", ikev2.DHToString(dhID)),
	)
	s.Logger.Info("IKE SA 协商画像",
		logger.String("profile", classifyIKEProfile(encrID, integID, prfID)),
		logger.String("encr", ikev2.EncrToString(encrID)),
		logger.String("integ", ikev2.IntegToString(integID)),
		logger.String("prf", ikev2.PRFToString(prfID)),
		logger.String("dh", ikev2.DHToString(dhID)),
	)

	// 设置加密实例
	s.PRFAlg, err = crypto.GetPRF(prfID)
	if err != nil {
		return fmt.Errorf("选择了不支持的 PRF: %d", prfID)
	}

	s.EncAlg, err = crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	if err != nil {
		return fmt.Errorf("选择了不支持的 Encr: %d", encrID)
	}
	s.ikeEncrID = encrID
	s.ikePRFID = prfID
	s.ikeEncrKeyLenBits = encrKeyLenBits
	s.ikeIsAEAD = encrID == uint16(ikev2.ENCR_AES_GCM_16) || encrID == uint16(ikev2.ENCR_AES_GCM_12) || encrID == uint16(ikev2.ENCR_AES_GCM_8)
	if s.ikeIsAEAD {
		s.ikeIntegID = 0
		s.IntegAlg, _ = crypto.GetIntegrityAlgorithm(0)
	} else {
		s.ikeIntegID = integID
		s.IntegAlg, err = crypto.GetIntegrityAlgorithm(integID)
		if err != nil {
			return fmt.Errorf("选择了不支持的 Integ: %d", integID)
		}
	}

	// 计算共享密钥
	if _, err := s.DH.ComputeSharedSecret(kePayload.KEData); err != nil {
		return fmt.Errorf("DH 计算失败: %v", err)
	}

	// 计算密钥
	s.Logger.Debug("正在生成密钥材料")
	if err := s.GenerateIKESAKeys(s.nr); err != nil {
		return err
	}

	s.sendCookie = false
	return nil
}

// ErrInvalidKEGroup 表示服务在 SA_INIT 阶段拒绝了我们的 DH Group
// 并在 PreferredGroup 字段中携带期望的群组 ID
type ErrInvalidKEGroup struct {
	PreferredGroup uint16
}

func (e *ErrInvalidKEGroup) Error() string {
	return fmt.Sprintf("服务器拒绝 DH Group，期望使用 Group %d", e.PreferredGroup)
}

// notifyTypeToString 将 IKEv2 错误类 Notify 类型转换为可读字符串
func notifyTypeToString(t uint16) string {
	switch t {
	case ikev2.UNSUPPORTED_CRITICAL_PAYLOAD:
		return "UNSUPPORTED_CRITICAL_PAYLOAD"
	case ikev2.INVALID_IKE_SPI:
		return "INVALID_IKE_SPI"
	case ikev2.INVALID_MAJOR_VERSION:
		return "INVALID_MAJOR_VERSION"
	case ikev2.INVALID_SYNTAX:
		return "INVALID_SYNTAX"
	case ikev2.INVALID_MESSAGE_ID:
		return "INVALID_MESSAGE_ID"
	case ikev2.INVALID_SPI:
		return "INVALID_SPI"
	case ikev2.NO_PROPOSAL_CHOSEN:
		return "NO_PROPOSAL_CHOSEN"
	case 17:
		return "INVALID_KE_PAYLOAD"
	case ikev2.AUTHENTICATION_FAILED:
		return "AUTHENTICATION_FAILED"
	case ikev2.TEMPORARY_FAILURE:
		return "TEMPORARY_FAILURE"
	case ikev2.CHILD_SA_NOT_FOUND:
		return "CHILD_SA_NOT_FOUND"
	default:
		return "UNKNOWN"
	}
}

func ParseRedirectData(data []byte) (string, error) {
	if len(data) < 1 {
		return "", errors.New("empty redirect data")
	}
	gwType := data[0]
	gwData := data[1:]

	switch gwType {
	case ikev2.RedirectGWIPv4: // IPv4
		if len(gwData) != 4 {
			return "", fmt.Errorf("invalid IPv4 length: %d", len(gwData))
		}
		return net.IP(gwData).String(), nil
	case ikev2.RedirectGWIPv6: // IPv6
		if len(gwData) != 16 {
			return "", fmt.Errorf("invalid IPv6 length: %d", len(gwData))
		}
		return net.IP(gwData).String(), nil
	case ikev2.RedirectGWFQDN: // FQDN
		return string(gwData), nil
	default:
		return "", fmt.Errorf("unknown gateway identity type: %d", gwType)
	}
}
