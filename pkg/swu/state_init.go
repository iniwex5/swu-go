package swu

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"time"

	//"encoding/hex"
	"errors"
	"fmt"

	"github.com/iniwex5/swu-go/pkg/crypto"
	"github.com/iniwex5/swu-go/pkg/ikev2"
	"github.com/iniwex5/swu-go/pkg/logger"
)

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

	if s.DH == nil {
		var err error
		s.DH, err = crypto.NewDiffieHellman(14)
		if err != nil {
			return nil, err
		}
		if err := s.DH.GenerateKey(); err != nil {
			return nil, err
		}
	}

	propCBC := ikev2.NewProposal(1, ikev2.ProtoIKE, nil)
	propCBC.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 128)
	propCBC.AddTransform(ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA2_256_128, 0)
	propCBC.AddTransform(ikev2.TransformTypePRF, ikev2.PRF_HMAC_SHA2_256, 0)
	propCBC.AddTransform(ikev2.TransformTypeDH, ikev2.MODP_2048_bit, 0)

	propGCM := ikev2.NewProposal(2, ikev2.ProtoIKE, nil)
	propGCM.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_GCM_16, 128)
	propGCM.AddTransform(ikev2.TransformTypePRF, ikev2.PRF_HMAC_SHA2_256, 0)
	propGCM.AddTransform(ikev2.TransformTypeDH, ikev2.MODP_2048_bit, 0)

	saPayload := &ikev2.EncryptedPayloadSA{
		Proposals: []*ikev2.Proposal{propCBC, propGCM},
	}

	kePayload := &ikev2.EncryptedPayloadKE{
		DHGroup: ikev2.MODP_2048_bit,
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

	payloads := []ikev2.Payload{saPayload, kePayload, noncePayload}
	if s.sendCookie && len(s.cookie) > 0 {
		payloads = append(payloads, &ikev2.EncryptedPayloadNotify{
			ProtocolID: 0,
			NotifyType: ikev2.COOKIE,
			NotifyData: s.cookie,
		})
	}
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
			// 检查错误，如 NO_PROPOSAL_CHOSEN
			if v.NotifyType == 14 { // NO_PROPOSAL_CHOSEN
				return errors.New("服务器拒绝了提议 (NO_PROPOSAL_CHOSEN)")
			}
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
			logger.Info("检测到 NAT，切换到 UDP 4500")
		}
	}

	// 处理 SA 选择 (简化: 假设服务器接受了我们的提议)
	// 我们应该解析 `saPayload.Proposals[0]` 以查看选择了什么。
	// 获取转换。
	selProp := saPayload.Proposals[0]
	var prfID uint16
	var encrID uint16
	var integID uint16
	// var dhID uint16

	for _, t := range selProp.Transforms {
		switch t.Type {
		case ikev2.TransformTypeEncr:
			encrID = uint16(t.ID)
		case ikev2.TransformTypeInteg:
			integID = uint16(t.ID)
		case ikev2.TransformTypePRF:
			prfID = uint16(t.ID)
		case ikev2.TransformTypeDH:
			// dhID = uint16(t.ID)
		}
	}

	// 设置加密实例
	s.PRFAlg, err = crypto.GetPRF(prfID)
	if err != nil {
		return fmt.Errorf("选择了不支持的 PRF: %d", prfID)
	}

	s.EncAlg, err = crypto.GetEncrypter(encrID)
	if err != nil {
		return fmt.Errorf("选择了不支持的 Encr: %d", encrID)
	}
	s.ikeEncrID = encrID
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
	logger.Debug("正在生成密钥材料")
	if err := s.GenerateIKESAKeys(s.nr); err != nil {
		return err
	}

	s.sendCookie = false
	return nil
}
