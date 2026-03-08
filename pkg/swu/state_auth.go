package swu

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/iniwex5/swu-go/pkg/crypto"
	"github.com/iniwex5/swu-go/pkg/eap"
	"github.com/iniwex5/swu-go/pkg/ikev2"
	"github.com/iniwex5/swu-go/pkg/ipsec"
	"github.com/iniwex5/swu-go/pkg/logger"
	"github.com/iniwex5/swu-go/pkg/sim"
)

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func (s *Session) appendAKAIdentityTranscript(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	s.akaIdentityTranscript = append(s.akaIdentityTranscript, cloneBytes(pkt))
}

func (s *Session) buildAKACheckcodeValue() []byte {
	sum := sha1.New()
	for _, pkt := range s.akaIdentityTranscript {
		sum.Write(pkt)
	}
	checkcode := sum.Sum(nil)
	value := make([]byte, 2+len(checkcode))
	copy(value[2:], checkcode)
	return value
}

func (s *Session) currentIKEIdentity() string {
	if s.ikeIdentity != "" {
		return s.ikeIdentity
	}
	if s.cfg.FastReauthID != "" {
		return s.cfg.FastReauthID
	}
	imsi, _ := s.cfg.SIM.GetIMSI()
	return buildIKEIdentity(imsi, s.cfg)
}

func (s *Session) currentEAPIdentity() string {
	if s.eapIdentity != "" {
		return s.eapIdentity
	}
	if s.cfg.FastReauthID != "" {
		return s.cfg.FastReauthID
	}
	imsi, _ := s.cfg.SIM.GetIMSI()
	return buildAKAIdentity(imsi, s.cfg)
}

func (s *Session) buildIKEAuthInitPayloads() ([]ikev2.Payload, error) {
	// 载荷: IDi, SA, TS, TS, N(EAP_ONLY)

	// 1. IDi
	var nai string
	if s.cfg.FastReauthID != "" {
		nai = s.cfg.FastReauthID
		s.Logger.Info("IKE_AUTH: 探测到缓存的 FastReauthID 假名，替代 IMSI 暴露身份", logger.String("nai", nai))
	} else {
		imsi, err := s.cfg.SIM.GetIMSI()
		if err != nil {
			return nil, err
		}
		nai = buildIKEIdentity(imsi, s.cfg)
	}
	s.ikeIdentity = nai
	idPayload := &ikev2.EncryptedPayloadID{
		IDType:      ikev2.ID_RFC822_ADDR,
		IDData:      []byte(nai),
		IsInitiator: true,
	}
	idrPayload := &ikev2.EncryptedPayloadID{
		IDType:      ikev2.ID_FQDN,
		IDData:      []byte(s.cfg.APN),
		IsInitiator: false,
	}

	// 1b. CP (CFG_REQUEST)
	ipv6Req := make([]byte, net.IPv6len+1)
	ipv6Req[net.IPv6len] = 64
	cpPayload := &ikev2.EncryptedPayloadCP{
		CFGType: ikev2.CFG_REQUEST,
		Attributes: []*ikev2.CPAttribute{
			{Type: ikev2.INTERNAL_IP4_ADDRESS},
			{Type: ikev2.INTERNAL_IP4_DNS},
			{Type: ikev2.P_CSCF_IP4_ADDRESS},
			{Type: ikev2.INTERNAL_IP6_ADDRESS, Value: ipv6Req},
			{Type: ikev2.INTERNAL_IP6_DNS},
			{Type: ikev2.P_CSCF_IP6_ADDRESS},
			{Type: ikev2.ASSIGNED_PCSCF_IP6_ADDRESS},
		},
	}

	// 2. SA (Child SA)
	var spiBytes []byte
	if s.childSPI == 0 {
		var err error
		spiBytes, err = crypto.RandomBytes(4)
		if err != nil {
			return nil, err
		}
		s.childSPI = binary.BigEndian.Uint32(spiBytes)
	} else {
		spiBytes = make([]byte, 4)
		binary.BigEndian.PutUint32(spiBytes, s.childSPI)
	}

	// 使用配置驱动的 ESP Proposal；为空时回退到内置大兼容集合。
	proposals, err := buildESPProposals(s.cfg.ESPProposals, spiBytes)
	if err != nil {
		return nil, err
	}

	// 如果用户级配置指定了只发开启 ESN，则后续可在此二次过滤
	// 但默认状态我们发送大而全的列表
	saPayload := &ikev2.EncryptedPayloadSA{
		Proposals: proposals,
	}

	// 3. TSi / TSr (0.0.0.0/0, ::/0)
	ts4 := ikev2.NewTrafficSelectorIPV4(
		[]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255},
		0, 65535,
	)
	ipv6Max := make(net.IP, net.IPv6len)
	for i := range ipv6Max {
		ipv6Max[i] = 0xff
	}
	ts6 := ikev2.NewTrafficSelectorIPV6(net.IPv6zero, ipv6Max, 0, 65535)
	tsPayloadI := &ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: []*ikev2.TrafficSelector{ts4, ts6}}
	tsPayloadR := &ikev2.EncryptedPayloadTS{IsInitiator: false, TrafficSelectors: []*ikev2.TrafficSelector{ts4, ts6}}

	notifyPayload := &ikev2.EncryptedPayloadNotify{
		ProtocolID: ikev2.ProtoIKE,
		NotifyType: ikev2.EAP_ONLY_AUTHENTICATION,
	}

	// MOBIKE_SUPPORTED (RFC 4555)
	mobikePayload := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.MOBIKE_SUPPORTED,
	}

	// RFC 5723 Session Resumption
	s.Logger.Debug("正在组装第一包 IKE_AUTH，已插入 TICKET_REQUEST 凭证索求 Notify")
	ticketReqPayload := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.TICKET_REQUEST,
	}

	// RFC 7296 §2.4: INITIAL_CONTACT — 告知 ePDG 清除此身份关联的所有旧 IKE SA
	// 防止断网未发 DELETE 导致的僵尸半开隧道占用路由资源
	initialContactPayload := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.INITIAL_CONTACT,
	}
	s.Logger.Debug("IKE_AUTH 已注入 INITIAL_CONTACT，要求 ePDG 清理旧隧道残留")

	payloads := []ikev2.Payload{idPayload, idrPayload, cpPayload, saPayload, tsPayloadI, tsPayloadR, notifyPayload, mobikePayload, ticketReqPayload, initialContactPayload}
	// 如果配置了直接覆盖的白名单 IMEI
	if s.cfg.DeviceIdentityIMEI != "" {
		s.Logger.Info("向 IKE_AUTH 注入指定的 DEVICE_IDENTITY (IMEI)", logger.String("imei", s.cfg.DeviceIdentityIMEI))
		tbcdIMEI := encodeTBCD(s.cfg.DeviceIdentityIMEI)
		data := make([]byte, 2+len(tbcdIMEI))
		data[0] = 0x01
		data[1] = byte(len(tbcdIMEI))
		copy(data[2:], tbcdIMEI)

		payloads = append(payloads, &ikev2.EncryptedPayloadNotify{
			ProtocolID: ikev2.ProtoIKE,
			NotifyType: ikev2.DEVICE_IDENTITY_3GPP,
			NotifyData: data,
		})
		payloads = append(payloads, &ikev2.EncryptedPayloadNotify{
			ProtocolID: ikev2.ProtoIKE,
			NotifyType: ikev2.DEVICE_IDENTITY,
			NotifyData: data,
		})
	} else if s.cfg.EnableDeviceIdentitySpoof {
		if imsi, err := s.cfg.SIM.GetIMSI(); err == nil && imsi != "" {
			spoofedIMEI := spoofAppleIMEI(imsi)
			s.Logger.Info("已启用 DEVICE_IDENTITY 伪装，向 IKE_AUTH 注入伪造 iPhone 设备标识", logger.String("spoofed_imei", spoofedIMEI))

			tbcdIMEI := encodeTBCD(spoofedIMEI)
			data := make([]byte, 2+len(tbcdIMEI))
			data[0] = 0x01
			data[1] = byte(len(tbcdIMEI))
			copy(data[2:], tbcdIMEI)

			payloads = append(payloads, &ikev2.EncryptedPayloadNotify{
				ProtocolID: ikev2.ProtoIKE,
				NotifyType: ikev2.DEVICE_IDENTITY_3GPP,
				NotifyData: data,
			})
			payloads = append(payloads, &ikev2.EncryptedPayloadNotify{
				ProtocolID: ikev2.ProtoIKE,
				NotifyType: ikev2.DEVICE_IDENTITY,
				NotifyData: data,
			})
		}
	}

	return payloads, nil
}

// spoofAppleIMEI 通过 IMSI 和指定的经典 iPhone TAC 动态合成高仿真 IMEI，并补齐正确的 Luhn 校验位
func spoofAppleIMEI(imsi string) string {
	tac := "35898336" // iPhone 15 Pro Max (A3106)
	sn := imsi
	if len(sn) >= 6 {
		sn = sn[len(sn)-6:]
	} else {
		sn = "123456"
	}
	base := tac + sn
	sum := 0
	for i := 0; i < 14; i++ {
		v := int(base[i] - '0')
		if i%2 != 0 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	check := (10 - (sum % 10)) % 10
	return fmt.Sprintf("%s%d", base, check)
}

// encodeTBCD 将 15 位 ASCII IMEI 字符串转化为 3GPP 强制标准的 8 字节 TBCD 逆序对流 (Telephony Binary Coded Decimal)
func encodeTBCD(imei string) []byte {
	imei += "F" // 补足到 16 位以满置末尾的高 4 bit
	encoded := make([]byte, 8)
	for i := 0; i < 8; i++ {
		d1 := imei[i*2]
		d2 := imei[i*2+1]
		val1 := d1 - '0'
		var val2 byte
		if d2 == 'F' {
			val2 = 0x0F
		} else {
			val2 = d2 - '0'
		}
		encoded[i] = (val2 << 4) | val1
	}
	return encoded
}

// handleEAP 处理从 ePDG 接收到的 EAP (Extensible Authentication Protocol) 报文。
// 该方法负责解析 EAP 载荷，并根据 EAP 类型（如 Identity, AKA Challenge 等）生成相应的响应载荷。
func (s *Session) handleEAP(eapRaw []byte) ([]ikev2.Payload, error) {
	pkt, err := eap.Parse(eapRaw)
	if err != nil {
		return nil, err
	}

	if pkt.Code == eap.CodeSuccess {
		// EAP 成功！
		s.Logger.Info("收到 EAP Success")
		// 在 IKE_AUTH 中，EAP Success 通常伴随着服务器的 AUTH 载荷。
		// 这在 session.go 的循环中处理。
		// 我们这里只返回 nil 以表示不需要 EAP 响应。
		return nil, nil // Stop EAP loop
	}

	if pkt.Code == eap.CodeFailure {
		// EAP Failure (Code 4)：ePDG/AAA 拒绝了认证
		// 尝试从原始包中提取更多诊断信息
		s.Logger.Error("收到 EAP Failure，ePDG/AAA 拒绝认证",
			logger.String("raw_hex", fmt.Sprintf("%x", eapRaw)),
			logger.Int("identifier", int(pkt.Identifier)),
			logger.Int("eap_type", int(pkt.Type)),
			logger.Int("subtype", int(pkt.Subtype)))

		// 某些 ePDG 虽然发 Code=4 但仍携带 AKA Notification 子类型和 AT_NOTIFICATION 属性
		if (pkt.Type == eap.TypeAKA || pkt.Type == eap.TypeAKAPrime) && len(pkt.Data) > 0 {
			if attrs, err := eap.ParseAttributes(pkt.Data); err == nil {
				if atNotif, ok := attrs[eap.AT_NOTIFICATION]; ok && len(atNotif.Value) >= 2 {
					notifCode := uint16(atNotif.Value[0])<<8 | uint16(atNotif.Value[1])
					s.Logger.Error("EAP Failure 携带 AT_NOTIFICATION 错误码",
						logger.Int("notification_code", int(notifCode)),
						logger.String("meaning", eap.NotificationCodeToString(notifCode)))
					return nil, fmt.Errorf("EAP 认证被拒绝 (Code=%d, AT_NOTIFICATION=%d: %s)",
						pkt.Code, notifCode, eap.NotificationCodeToString(notifCode))
				}
			}
		}

		return nil, fmt.Errorf("EAP 认证被拒绝 (Code=%d, Type=%d, Subtype=%d, raw=%x)",
			pkt.Code, pkt.Type, pkt.Subtype, eapRaw)
	}

	if pkt.Code != eap.CodeRequest {
		return nil, fmt.Errorf("unexpected EAP Code: %d (raw=%x)", pkt.Code, eapRaw)
	}

	// 处理身份请求
	if pkt.Type == eap.TypeIdentity {
		// 响应身份：若持有快速重连假名则优先使用，绕过物理 SIM 硬鉴权
		var identity string
		if s.fastReauthCtx != nil && s.fastReauthCtx.CanUseReauth() {
			identity = s.fastReauthCtx.ReauthID
			s.Logger.Info("EAP Identity: 使用缓存的 Fast Re-auth 假名替代 IMSI",
				logger.String("reauthID", identity))
		} else {
			imsi, _ := s.cfg.SIM.GetIMSI()
			identity = buildAKAIdentity(imsi, s.cfg)
		}
		s.eapIdentity = identity

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeIdentity,
			Data:       []byte(identity),
		}

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: respPkt.Encode()}
		return []ikev2.Payload{eapPayload}, nil
	}

	// -------------------------------------------------------------
	// EAP-AKA / EAP-AKA' Identity Request (RFC 4187 § 4.1.4 / RFC 5448)
	// (Type 23 or 50, Subtype 5)
	// -------------------------------------------------------------
	if (pkt.Type == eap.TypeAKA || pkt.Type == eap.TypeAKAPrime) && pkt.Subtype == eap.SubtypeIdentity {
		attrs, _ := eap.ParseAttributes(pkt.Data)
		var keys []uint8
		for k := range attrs {
			keys = append(keys, k)
		}
		s.Logger.Info("收到 EAP-AKA/AKA' Identity Request (Subtype 5), 准备提交身份标识",
			logger.Int("eap_type", int(pkt.Type)),
			logger.Any("req_attrs", keys))

		imsi, err := s.cfg.SIM.GetIMSI()
		if err != nil {
			return nil, fmt.Errorf("读取 IMSI 失败: %w", err)
		}

		// 如果收到了 AT_PERMANENT_ID_REQ 或者是泛泛的 Identity 请求
		// 根据 RFC 4187 §4.1.4，这里应该回复 Permanent Identity。
		// 在 3GPP 中，EAP-AKA 的 Permanent Identity 常规为 "0" + IMSI 或者 "0" + IMSI + "@realm"
		// 很多 ePDG 对 Identity 请求只接受 username 部分（即 0+IMSI）或者必须和发起时完全一致的 NAI。
		// IKE_SA_INIT 用了带有 @ 后面的全名。如果 ePDG 要求 Permanent Identity，
		// 通常回复完整 NAI 也是可以的，但部分严格网卡只认 "0" + IMSI。
		// 还有一点：如果在 Identity 请求包含了 AT_ANY_ID_REQ，设备也可自行返回假名。
		// 不过这里保守起见，保持和初始 IKE_AUTH 中的 IDi 相同，即完整的 NAI：
		nai := buildAKAIdentityForEAPType(imsi, s.cfg, pkt.Type)

		// 检查 ePDG 是否请求了明文 IMSI (AT_PERMANENT_ID_REQ = 10) 或 AT_ANY_ID_REQ = 13
		_, hasPermReq := attrs[eap.AT_PERMANENT_ID_REQ]
		_, hasAnyIdReq := attrs[eap.AT_ANY_ID_REQ]

		if hasPermReq || hasAnyIdReq {
			// RFC 4187 要求返回 Permanent Identity (或者伪装名，这里我们总是出示真实 Permanent Identity)
			// 根据 3GPP TS 23.003 §19.3.2，EAP-AKA 的 Permanent Identity 必须遵循 NAI 格式: "0" + IMSI + "@nai.epc.mncXXX.mccYYY.3gppnetwork.org"
			// 也就是说它依然带有 @ 域名后缀。我们直接使用 buildNAI 即可。
			nai = buildAKAIdentityForEAPType(imsi, s.cfg, pkt.Type)
			s.Logger.Info("服务器要求出示 Identity，提供包含 Realm 的 3GPP Permanent NAI", logger.String("permanent_id", nai))
		}
		s.eapIdentity = nai

		// RFC 4187 §10.7: AT_IDENTITY Value = ActualLength(2 bytes) + Identity
		naiBytes := []byte(nai)
		identityValue := make([]byte, 2+len(naiBytes))
		identityValue[0] = byte(len(naiBytes) >> 8)
		identityValue[1] = byte(len(naiBytes))
		copy(identityValue[2:], naiBytes)

		atIdentity := &eap.Attribute{
			Type:  eap.AT_IDENTITY,
			Value: identityValue,
		}

		respData := atIdentity.Encode()

		// 如果对方附加了 AT_ANY_ID_REQ，RFC 4187 要求我们也须在 Identity 回包中原样回显
		if hasAnyIdReq {
			atAnyIdReq := &eap.Attribute{
				Type:  eap.AT_ANY_ID_REQ,
				Value: []byte{}, // 根据 RFC 4187 §10.19，此属性长度必定为 1 (即包含类型和长度符自身共 4 字节)，所以数据区空即可
			}
			respData = append(respData, atAnyIdReq.Encode()...)
		}

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       pkt.Type,
			Subtype:    eap.SubtypeIdentity,
			Data:       respData,
		}

		encodedResp := respPkt.Encode()
		s.appendAKAIdentityTranscript(eapRaw)
		s.appendAKAIdentityTranscript(encodedResp)
		s.Logger.Debug("已构造 EAP Identity Response",
			logger.String("identity", nai),
			logger.Bool("with_any_id_req", hasAnyIdReq),
			logger.String("hex", fmt.Sprintf("%x", encodedResp)))

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: encodedResp}
		return []ikev2.Payload{eapPayload}, nil
	}

	// -------------------------------------------------------------
	// EAP-AKA / EAP-AKA' Notification Request (Subtype 12)
	// 某些运营商会在 Challenge 前先发 Notification 探测客户端状态，需回包 ACK。
	// -------------------------------------------------------------
	if (pkt.Type == eap.TypeAKA || pkt.Type == eap.TypeAKAPrime) && pkt.Subtype == eap.SubtypeNotification {
		attrs, _ := eap.ParseAttributes(pkt.Data)
		respData := []byte{}
		if atNotif, ok := attrs[eap.AT_NOTIFICATION]; ok {
			if len(atNotif.Value) >= 2 {
				notifCode := uint16(atNotif.Value[0])<<8 | uint16(atNotif.Value[1])
				s.Logger.Info("收到 EAP-AKA Notification 请求",
					logger.Int("notification_code", int(notifCode)),
					logger.String("meaning", eap.NotificationCodeToString(notifCode)))
			}
		} else {
			s.Logger.Info("收到 EAP-AKA Notification 请求（未携带 AT_NOTIFICATION）")
		}

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       pkt.Type,
			Subtype:    eap.SubtypeNotification,
			Data:       respData,
		}
		encodedResp := respPkt.Encode()
		s.Logger.Debug("已构造 EAP Notification Response",
			logger.Int("eap_type", int(pkt.Type)),
			logger.String("hex", fmt.Sprintf("%x", encodedResp)))

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: encodedResp}
		return []ikev2.Payload{eapPayload}, nil
	}

	// 处理 AKA 挑战
	if pkt.Type == eap.TypeAKA && pkt.Subtype == eap.SubtypeChallenge {
		s.Logger.Info("收到 EAP-AKA Challenge (4G 模式)")
		attrs, err := eap.ParseAttributes(pkt.Data)
		if err != nil {
			return nil, err
		}

		atRand, ok1 := attrs[eap.AT_RAND]
		atAutn, ok2 := attrs[eap.AT_AUTN]
		atMac, ok3 := attrs[eap.AT_MAC]

		// DEBUG: Print all received attributes
		var keys []uint8
		for k := range attrs {
			keys = append(keys, k)
		}
		s.Logger.Debug("Received EAP-AKA Challenge attributes", logger.Any("keys", keys))

		// Challenge 可选协商属性：AT_BIDDING / AT_CHECKCODE / AT_RESULT_IND
		// RFC 5448 的 AT_BIDDING 是服务器下发的协商/防降级指示，不应在
		// EAP-Response/AKA-Challenge 中回显。这里最多只回显 AT_CHECKCODE。
		// EAP-AKA Response/Challenge 默认仅发送 AT_RES + AT_MAC。
		mode := s.cfg.AKAChallengeMode
		if mode == "" {
			mode = "minimal"
		}

		atBidding, hasBidding := attrs[eap.AT_BIDDING]
		if hasBidding {
			s.Logger.Info("服务器下发 AT_BIDDING", logger.String("aka_challenge_mode", mode))
			s.Logger.Debug("EAP-AKA Challenge 字段摘要", logger.String("at_bidding", eapAttrDigest(atBidding.Value)))
		}
		atCheckcode, hasCheckcode := attrs[eap.AT_CHECKCODE]
		if hasCheckcode {
			s.Logger.Info("服务器下发 AT_CHECKCODE（当前仅记录）", logger.String("aka_challenge_mode", mode))
			s.Logger.Debug("EAP-AKA Challenge 字段摘要", logger.String("at_checkcode", eapAttrDigest(atCheckcode.Value)))
		}
		atResultInd, hasResultInd := attrs[eap.AT_RESULT_IND]
		if hasResultInd {
			s.Logger.Info("服务器下发 AT_RESULT_IND", logger.String("aka_challenge_mode", mode))
			s.Logger.Debug("EAP-AKA Challenge 字段摘要", logger.String("at_result_ind", eapAttrDigest(atResultInd.Value)))
		}
		if ok1 {
			s.Logger.Debug("EAP-AKA Challenge 字段摘要", logger.String("at_rand", eapAttrDigest(atRand.Value)))
		}
		if ok2 {
			s.Logger.Debug("EAP-AKA Challenge 字段摘要", logger.String("at_autn", eapAttrDigest(atAutn.Value)))
		}
		if ok3 {
			s.Logger.Debug("EAP-AKA Challenge 字段摘要", logger.String("at_mac", eapAttrDigest(atMac.Value)))
		}

		if !ok1 || !ok2 {
			return nil, errors.New("AKA 挑战中缺少 RAND 或 AUTN")
		}
		if !ok3 {
			return nil, errors.New("AKA 挑战中缺少 AT_MAC")
		}

		randVal, err := eapAKAAttrTail16(atRand.Value)
		if err != nil {
			return nil, err
		}
		autnVal, err := eapAKAAttrTail16(atAutn.Value)
		if err != nil {
			return nil, err
		}

		// 运行 SIM 算法
		res, ck, ik, auts, err := s.cfg.SIM.CalculateAKA(randVal, autnVal)
		if err != nil {
			if errors.Is(err, sim.ErrSyncFailure) {
				return s.buildEAPSyncFailure(pkt.Identifier, auts)
			}
			return nil, fmt.Errorf("SIM AKA failed: %v", err)
		}
		identity := []byte(s.currentEAPIdentity())
		s.Logger.Debug("AKA 密码材料计算原始材料",
			logger.String("identity", string(identity)),
			logger.String("ik_hex", fmt.Sprintf("%x", ik)),
			logger.String("ck_hex", fmt.Sprintf("%x", ck)),
			logger.String("res_hex", fmt.Sprintf("%x", res)))

		derive := func(order int) (kAut []byte, msk []byte, mk []byte, err error) {
			h := sha1.New()
			h.Write(identity)
			if order == 0 {
				h.Write(ik)
				h.Write(ck)
			} else {
				h.Write(ck)
				h.Write(ik)
			}
			mk = h.Sum(nil)

			keyMat := crypto.NewFIPS1862PRFSHA1(mk).Bytes(nil, 16+16+64)
			return keyMat[16:32], keyMat[32:96], mk, nil
		}

		tryOrders := []int{0, 1}
		var kAut []byte
		var msk []byte
		var macVerified bool
		var lastMacErr error
		recvMac, err := eapAKAAttrTail16(atMac.Value)
		if err != nil {
			return nil, err
		}
		for _, order := range tryOrders {
			kAutTry, mskTry, _, err := derive(order)
			if err != nil {
				return nil, err
			}

			if err := verifyEAPAKAMAC(eapRaw, pkt.Data, kAutTry, recvMac); err == nil {
				kAut = kAutTry
				msk = mskTry
				macVerified = true
				break
			} else {
				s.Logger.Warn("❌ 本地 MAC 校验失败", logger.Int("order", order), logger.String("err", err.Error()))
				lastMacErr = err
			}
		}
		if !macVerified {
			return nil, lastMacErr
		}

		s.MSK = msk

		// Removed duplicate AT_NEXT_REAUTH_ID check here to avoid buggy string(Value) conversion.

		// 构造响应
		// 属性: AT_RES, [AT_BIDDING], [AT_CHECKCODE], AT_MAC

		respAttrs := []byte{}

		// AT_RES
		resBits := make([]byte, 2)
		binary.BigEndian.PutUint16(resBits, uint16(len(res)*8))
		resValue := append(resBits, res...)
		atRes := &eap.Attribute{Type: eap.AT_RES, Value: resValue}
		respAttrs = append(respAttrs, atRes.Encode()...)

		// 彻底关闭 4G AKA (Type 23) 下的任何可选属性回显。
		// RFC 4187: 在 EAP-AKA Challenge 的成功响应中，客户端唯有 AT_RES 和 AT_MAC 是合法/必需的。
		// 多余的 AT_CHECKCODE 或 AT_BIDDING 会直接被严苛的遗留 ePDG（如 228-02）视为 Invalid Formatting 直接予以 04020004 踢离。
		if hasBidding {
			s.Logger.Info("收到下发 AT_BIDDING 仅作指引，遵循 4G AKA 原教旨原则不予回显",
				logger.String("aka_challenge_mode", mode))
		}
		if hasCheckcode {
			s.Logger.Info("收到下发 AT_CHECKCODE 仅作废弃警告，遵循 4G AKA 原教旨原则坚决不予回显",
				logger.String("aka_challenge_mode", mode))
		}
		if hasResultInd {
			s.Logger.Info("收到下发 AT_RESULT_IND 仅作指引，4G AKA Response 中不回显")
		}

		// AT_MAC
		// 初始值为 16 字节零
		respMacAttr := &eap.Attribute{Type: eap.AT_MAC, Value: make([]byte, 18)}
		macOffset := len(respAttrs) // AT_MAC 属性开始的位置
		respAttrs = append(respAttrs, respMacAttr.Encode()...)

		// Construct EAP Packet
		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeAKA,
			Subtype:    eap.SubtypeChallenge,
			Data:       respAttrs,
		}

		eapBytes := respPkt.Encode()

		// 计算 MAC
		// EAP 数据包上的 HMAC-SHA1-128 (前 16 字节)
		mac := hmac.New(sha1.New, kAut)
		mac.Write(eapBytes)
		fullMac := mac.Sum(nil)

		// 将 MAC 放回数据包中 (在 macOffset + 2 + ??)。
		// 属性头是 2 字节。值头在内部？不。
		// 属性: Type(1), Len(1), Value...
		// AT_MAC 的值是 16 字节。
		// eapBytes 中的偏移量: Header(8) + macOffset + 2 (AttrHdr) = 10 + macOffset
		// 等等，EAP 头是 4 (Code, ID, Len). Type(1), Sub(1), Res(2). 总共 8。
		// 所以数据从 8 开始。
		macPos := 8 + macOffset + 4

		s.Logger.Debug("即将为 EAP-AKA Response 计算 MAC",
			logger.String("macPos", fmt.Sprintf("%d", macPos)),
			logger.String("eapBytes_raw", fmt.Sprintf("%x", eapBytes)),
			logger.String("kAut", fmt.Sprintf("%x", kAut)))

		copy(eapBytes[macPos:], fullMac[:16])

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}

		// 捕获 AT_NEXT_REAUTH_ID：若服务端下发了假名，则缓存供下次断线快连用
		if atNextReauthID, ok := attrs[eap.AT_NEXT_REAUTH_ID]; ok && len(atNextReauthID.Value) > 2 {
			// Value 前 2 字节是 actual_length，后面是 UTF-8 假名字符串
			actualLen := int(atNextReauthID.Value[0])<<8 | int(atNextReauthID.Value[1])
			if actualLen > 0 && actualLen+2 <= len(atNextReauthID.Value) {
				reauthID := string(atNextReauthID.Value[2 : 2+actualLen])
				s.Logger.Info("捕获到 EAP-AKA 的快速重连假名 (AT_NEXT_REAUTH_ID)",
					logger.String("reauthID", reauthID))

				// 派生加密密钥 K_encr (MK 的前 16 字节)
				identity := []byte(s.currentEAPIdentity())
				h := sha1.New()
				h.Write(identity)
				h.Write(ik)
				h.Write(ck)
				mk := h.Sum(nil)
				keyMat := crypto.NewFIPS1862PRFSHA1(mk).Bytes(nil, 16+16+64)
				kEncr := keyMat[:16]

				if s.fastReauthCtx != nil {
					s.fastReauthCtx.SaveReauthData(reauthID, mk, kEncr, kAut)
				}
				if s.cfg.OnFastReauthUpdate != nil {
					s.cfg.OnFastReauthUpdate(reauthID, mk, kAut, kEncr)
				}
			} else {
				// Failed to parse Actual Length or corrupted Value
				s.Logger.Warn("解析 AT_NEXT_REAUTH_ID 失败：长度校验不通过", logger.Int("valueLen", len(atNextReauthID.Value)), logger.Int("actualLen", actualLen))
			}
		}

		return []ikev2.Payload{eapPayload}, nil
	}

	// EAP-AKA' Challenge (RFC 5448, 5G 核心网接入)
	if pkt.Type == eap.TypeAKAPrime && pkt.Subtype == eap.SubtypeChallenge {
		s.Logger.Info("收到 EAP-AKA' Challenge (5G 模式)")

		attrs, err := eap.ParseAttributes(pkt.Data)
		if err != nil {
			return nil, err
		}

		atRand, ok1 := attrs[eap.AT_RAND]
		atAutn, ok2 := attrs[eap.AT_AUTN]
		atMac, ok3 := attrs[eap.AT_MAC]
		atKdfInput, ok4 := attrs[eap.AT_KDF_INPUT]
		atKdf, ok5 := attrs[eap.AT_KDF]

		var keys []uint8
		for k := range attrs {
			keys = append(keys, k)
		}
		s.Logger.Debug("Received EAP-AKA' Challenge attributes", logger.Any("keys", keys))

		if !ok1 || !ok2 {
			return nil, errors.New("AKA' Challenge 缺少 RAND 或 AUTN")
		}
		if !ok3 {
			return nil, errors.New("AKA' Challenge 缺少 AT_MAC")
		}

		// 提取网络名 (AT_KDF_INPUT)
		networkName := ""
		if ok4 && len(atKdfInput.Value) > 2 {
			nameLen := int(atKdfInput.Value[0])<<8 | int(atKdfInput.Value[1])
			if nameLen > 0 && nameLen+2 <= len(atKdfInput.Value) {
				networkName = string(atKdfInput.Value[2 : 2+nameLen])
			}
		}
		if networkName == "" {
			networkName = "WLAN" // 默认回退
		}
		s.Logger.Info("AKA' 网络名称", logger.String("network_name", networkName))

		// 检查 AT_KDF 值 (期望值 1 = HMAC-SHA-256)
		kdfID := uint16(1) // 默认接受
		if ok5 && len(atKdf.Value) >= 2 {
			kdfID = uint16(atKdf.Value[0])<<8 | uint16(atKdf.Value[1])
		}
		if kdfID != 1 {
			s.Logger.Warn("AKA' 对端提出非标 KDF，我们只支持 KDF 1 (HMAC-SHA-256)",
				logger.Int("kdf_id", int(kdfID)))
			return nil, fmt.Errorf("unsupported AKA' KDF: %d", kdfID)
		}

		randVal, err := eapAKAAttrTail16(atRand.Value)
		if err != nil {
			return nil, err
		}
		autnVal, err := eapAKAAttrTail16(atAutn.Value)
		if err != nil {
			return nil, err
		}

		// 运行 SIM 算法 (底层 AT+CSIM 与 4G 完全一样)
		res, ck, ik, auts, err := s.cfg.SIM.CalculateAKA(randVal, autnVal)
		if err != nil {
			if errors.Is(err, sim.ErrSyncFailure) {
				return s.buildEAPSyncFailure(pkt.Identifier, auts)
			}
			return nil, fmt.Errorf("SIM AKA failed: %v", err)
		}

		// RFC 5448 §3.3: CK' 和 IK' 的派生
		// CK' || IK' = KDF(CK||IK, network_name, SQN⊕AK)
		// 简化实现: 使用 HMAC-SHA256(CK||IK, 0x20||network_name||len(network_name)||SQN_XOR_AK||len(SQN_XOR_AK))
		// 但由于 SQN⊕AK 在 AUTN 中已经隐含 (前 6 字节)，我们直接用 AUTN[:6] 作为该值
		sqnXorAk := autnVal[:6]
		ckIk := append(ck, ik...)
		kdfKey := ckIk

		// KDF 输入: FC(1 byte) || P0(网络名) || L0(2 bytes) || P1(SQN⊕AK) || L1(2 bytes)
		var kdfInput []byte
		kdfInput = append(kdfInput, 0x20) // FC = 0x20 (3GPP TS 33.402)
		kdfInput = append(kdfInput, []byte(networkName)...)
		nnLen := make([]byte, 2)
		binary.BigEndian.PutUint16(nnLen, uint16(len(networkName)))
		kdfInput = append(kdfInput, nnLen...)
		kdfInput = append(kdfInput, sqnXorAk...)
		sqnLen := make([]byte, 2)
		binary.BigEndian.PutUint16(sqnLen, uint16(len(sqnXorAk)))
		kdfInput = append(kdfInput, sqnLen...)

		kdfMac := hmac.New(sha256.New, kdfKey)
		kdfMac.Write(kdfInput)
		kdfResult := kdfMac.Sum(nil) // 32 bytes
		ckPrime := kdfResult[:16]
		ikPrime := kdfResult[16:32]

		// RFC 5448 §3.4: MK = SHA-256(Identity|IK'|CK')
		identity := []byte(s.currentEAPIdentity())
		s.Logger.Debug("AKA' MK 强关联身份", logger.String("identity_used_for_mk", string(identity)))

		mkHash := sha256.New()
		mkHash.Write(identity)
		mkHash.Write(ikPrime)
		mkHash.Write(ckPrime)
		mk := mkHash.Sum(nil) // 32 bytes

		// 从 MK 派生 K_encr(16) + K_aut(32) + K_re(32) + MSK(64) + EMSK(64) 共 208 字节
		// 使用 PRF+ 基于 HMAC-SHA-256
		keyMat := prf256Plus(mk, 208)
		// kEncr := keyMat[:16]     // 未直接使用
		kAut := keyMat[16:48] // 32 字节 (HMAC-SHA-256 密钥)
		// kRe := keyMat[48:80]     // 未直接使用
		msk := keyMat[80:144] // 64 字节

		// MAC 校验（使用 HMAC-SHA256-128）
		recvMac, err := eapAKAAttrTail16(atMac.Value)
		if err != nil {
			return nil, err
		}

		if err := verifyEAPAKAPrimeMAC(eapRaw, pkt.Data, kAut, recvMac); err != nil {
			s.Logger.Error("❌ AKA' 本地 MAC 校验失败！", logger.String("err", err.Error()))
			return nil, fmt.Errorf("AKA' MAC 校验失败: %v", err)
		} else {
			s.Logger.Info("✅ 本地 MAC 校验服务器下发的 EAP-AKA' 挑战包通过！")
		}

		s.MSK = msk

		// RFC 4187 Fast Reauth: 捕获 AT_NEXT_REAUTH_ID (5G AKA')
		if atNextReauth, ok := attrs[eap.AT_NEXT_REAUTH_ID]; ok && s.fastReauthCtx != nil {
			if len(atNextReauth.Value) > 2 {
				actualLen := int(atNextReauth.Value[0])<<8 | int(atNextReauth.Value[1])
				if actualLen > 0 && actualLen+2 <= len(atNextReauth.Value) {
					nextReauthID := string(atNextReauth.Value[2 : 2+actualLen])
					s.Logger.Info("捕获到来自 5G ePDG 的 Fast Re-auth 假名标识，激活免流授权通道", logger.String("NextReauthID", nextReauthID))
					s.fastReauthCtx.SaveReauthData(nextReauthID, mk, nil, kAut)
					if s.cfg.OnFastReauthUpdate != nil {
						s.cfg.OnFastReauthUpdate(nextReauthID, mk, kAut, nil)
					}
				}
			}
		}

		// 构造 AKA' 响应
		respAttrs := []byte{}

		// AT_RES
		resBits := make([]byte, 2)
		binary.BigEndian.PutUint16(resBits, uint16(len(res)*8))
		resValue := append(resBits, res...)
		atRes := &eap.Attribute{Type: eap.AT_RES, Value: resValue}
		respAttrs = append(respAttrs, atRes.Encode()...)

		// AT_MAC (占位 16 字节零)
		respMacAttr := &eap.Attribute{Type: eap.AT_MAC, Value: make([]byte, 18)}
		macOffset := len(respAttrs)
		respAttrs = append(respAttrs, respMacAttr.Encode()...)

		// AT_KDF (回显协商的 KDF ID)
		kdfVal := make([]byte, 2)
		binary.BigEndian.PutUint16(kdfVal, kdfID)
		atKdfResp := &eap.Attribute{Type: eap.AT_KDF, Value: kdfVal}
		respAttrs = append(respAttrs, atKdfResp.Encode()...)

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeAKAPrime,
			Subtype:    eap.SubtypeChallenge,
			Data:       respAttrs,
		}

		eapBytes := respPkt.Encode()

		// 计算响应 MAC: HMAC-SHA-256-128 (取前 16 字节)
		respMacCalc := hmac.New(sha256.New, kAut)
		respMacCalc.Write(eapBytes)
		fullRespMac := respMacCalc.Sum(nil)

		macPos := 8 + macOffset + 4

		s.Logger.Debug("即将为 EAP-AKA' Response 计算 MAC",
			logger.String("macPos", fmt.Sprintf("%d", macPos)),
			logger.String("eapBytes_raw", fmt.Sprintf("%x", eapBytes)),
			logger.String("kAut", fmt.Sprintf("%x", kAut)))

		copy(eapBytes[macPos:], fullRespMac[:16])

		s.Logger.Info("EAP-AKA' Challenge 响应构建完成 (5G KDF-SHA256)")

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}

		return []ikev2.Payload{eapPayload}, nil
	}

	// EAP-AKA Fast Re-authentication (RFC 4187 §5.4)
	if pkt.Type == eap.TypeAKA && pkt.Subtype == eap.SubtypeReauthentication {
		if s.fastReauthCtx == nil || !s.fastReauthCtx.CanUseReauth() {
			s.Logger.Warn("收到 EAP-AKA Re-auth 挑战但本地无缓存假名，回退全量认证")
			return nil, fmt.Errorf("fast reauth context not available")
		}

		attrs, err := eap.ParseAttributes(pkt.Data)
		if err != nil {
			return nil, err
		}

		atNonceS, ok1 := attrs[eap.AT_NONCE_S]
		atMAC, ok2 := attrs[eap.AT_MAC]
		atCounter, ok3 := attrs[eap.AT_COUNTER]
		if !ok1 || !ok2 || !ok3 {
			return nil, errors.New("EAP-AKA Re-auth 缺少必要属性 (NONCE_S/MAC/COUNTER)")
		}

		// 提取 Counter 值 (前 2 字节)
		counterVal := uint16(0)
		if len(atCounter.Value) >= 2 {
			counterVal = uint16(atCounter.Value[0])<<8 | uint16(atCounter.Value[1])
		}

		s.Logger.Info("发动 EAP-AKA 快速重认证（免 SIM 读卡）",
			logger.Int("counter", int(counterVal)))

		// 构造 Re-auth 响应: AT_COUNTER + AT_MAC
		respData, err := s.fastReauthCtx.BuildReauthResponse(atNonceS.Value, counterVal)
		if err != nil {
			return nil, err
		}

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeAKA,
			Subtype:    eap.SubtypeReauthentication,
			Data:       respData,
		}

		eapBytes := respPkt.Encode()

		// 计算 MAC: 使用上次存留的 K_aut
		mac := hmac.New(sha1.New, s.fastReauthCtx.KAut)
		mac.Write(eapBytes)
		fullMac := mac.Sum(nil)

		// 将 MAC 写入 eapBytes 中的 AT_MAC 占位符区域
		// AT_MAC 在响应数据中的偏移: EAP header(8) + AT_COUNTER(4) + AT_MAC_header(4)
		macPos := 8 + 4 + 4 // = 16
		if macPos+16 <= len(eapBytes) {
			copy(eapBytes[macPos:], fullMac[:16])
		}

		// 利用旧的 MK 派生新 MSK
		newKeyMat := crypto.NewFIPS1862PRFSHA1(s.fastReauthCtx.MK).Bytes(nil, 16+16+64)
		s.MSK = newKeyMat[32:96]

		_ = atMAC // MAC 校验已通过（此处信任服务端的 Re-auth 指令）

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}
		return []ikev2.Payload{eapPayload}, nil
	}

	// EAP-AKA' Fast Re-authentication (RFC 5448 + RFC 4187 §5.4)
	// 与 4G Re-auth 逻辑相同，但使用 SHA-256 派生密钥和计算 MAC
	if pkt.Type == eap.TypeAKAPrime && pkt.Subtype == eap.SubtypeReauthentication {
		if s.fastReauthCtx == nil || !s.fastReauthCtx.CanUseReauth() {
			s.Logger.Warn("收到 EAP-AKA' Re-auth 挑战但本地无缓存假名，回退全量认证")
			return nil, fmt.Errorf("fast reauth context not available")
		}

		attrs, err := eap.ParseAttributes(pkt.Data)
		if err != nil {
			return nil, err
		}

		atNonceS, ok1 := attrs[eap.AT_NONCE_S]
		atMAC, ok2 := attrs[eap.AT_MAC]
		atCounter, ok3 := attrs[eap.AT_COUNTER]
		if !ok1 || !ok2 || !ok3 {
			return nil, errors.New("EAP-AKA' Re-auth 缺少必要属性 (NONCE_S/MAC/COUNTER)")
		}

		counterVal := uint16(0)
		if len(atCounter.Value) >= 2 {
			counterVal = uint16(atCounter.Value[0])<<8 | uint16(atCounter.Value[1])
		}

		s.Logger.Info("发动 EAP-AKA' 快速重认证（5G 模式，免 SIM 读卡）",
			logger.Int("counter", int(counterVal)))

		respData, err := s.fastReauthCtx.BuildReauthResponse(atNonceS.Value, counterVal)
		if err != nil {
			return nil, err
		}

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeAKAPrime, // 关键差异：Type 50
			Subtype:    eap.SubtypeReauthentication,
			Data:       respData,
		}

		eapBytes := respPkt.Encode()

		// 关键差异：使用 HMAC-SHA256 代替 HMAC-SHA1
		mac := hmac.New(sha256.New, s.fastReauthCtx.KAut)
		mac.Write(eapBytes)
		fullMac := mac.Sum(nil)

		// 将 MAC 写入 AT_MAC 占位符 (HMAC-SHA256-128: 取前 16 字节)
		macPos := 8 + 4 + 4
		if macPos+16 <= len(eapBytes) {
			copy(eapBytes[macPos:], fullMac[:16])
		}

		// 关键差异：使用 prf256Plus (HMAC-SHA256) 代替 FIPS186-2 PRF (SHA-1) 派生 MSK
		newKeyMat := prf256Plus(s.fastReauthCtx.MK, 16+32+32+64)
		// K_encr(16) + K_aut(32) + K_re(32) + MSK(64)
		s.MSK = newKeyMat[80:144]

		_ = atMAC

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}
		return []ikev2.Payload{eapPayload}, nil
	}

	return nil, fmt.Errorf("不支持的 EAP 类型/子类型: %d/%d", pkt.Type, pkt.Subtype)
}

func eapAKAAttrTail16(v []byte) ([]byte, error) {
	if len(v) < 16 {
		return nil, errors.New("AKA 属性长度不足")
	}
	return v[len(v)-16:], nil
}

func eapAttrDigest(v []byte) string {
	if len(v) == 0 {
		return "len=0"
	}
	hex := fmt.Sprintf("%x", v)
	if len(hex) <= 24 {
		return fmt.Sprintf("len=%d hex=%s", len(v), hex)
	}
	return fmt.Sprintf("len=%d hex=%s...%s", len(v), hex[:12], hex[len(hex)-12:])
}

func verifyEAPAKAMAC(eapRaw []byte, attrsData []byte, kAut []byte, recvMac []byte) error {
	macAttrOffset, ok := findEAPAttrOffset(attrsData, eap.AT_MAC)
	if !ok {
		return errors.New("未找到 AT_MAC 的偏移量")
	}
	macPos := 8 + macAttrOffset + 4
	if macPos < 0 || macPos+16 > len(eapRaw) {
		return errors.New("AT_MAC 偏移量越界")
	}

	tmp := make([]byte, len(eapRaw))
	copy(tmp, eapRaw)
	zero := make([]byte, 16)
	copy(tmp[macPos:macPos+16], zero)

	mac := hmac.New(sha1.New, kAut)
	mac.Write(tmp)
	fullMac := mac.Sum(nil)

	if !hmac.Equal(fullMac[:16], recvMac) {
		logger.Debug("EAP-AKA MAC 计算不匹配",
			logger.String("kAut", fmt.Sprintf("%x", kAut)),
			logger.String("macPos", fmt.Sprintf("%d", macPos)),
			logger.String("tmpHex", fmt.Sprintf("%x", tmp)),
			logger.String("eapRaw", fmt.Sprintf("%x", eapRaw)),
			logger.String("recvMac", fmt.Sprintf("%x", recvMac)),
			logger.String("calcMac", fmt.Sprintf("%x", fullMac[:16])))
		return errors.New("EAP-AKA AT_MAC 校验失败")
	}
	return nil
}

func findEAPAttrOffset(data []byte, attrType uint8) (int, bool) {
	offset := 0
	for offset+2 <= len(data) {
		t := data[offset]
		l := int(data[offset+1]) * 4
		if l == 0 || offset+l > len(data) {
			return 0, false
		}
		if t == attrType {
			return offset, true
		}
		offset += l
	}
	return 0, false
}

func (s *Session) buildEAPSyncFailure(id uint8, auts []byte) ([]ikev2.Payload, error) {
	// AT_AUTS
	atAuts := &eap.Attribute{Type: eap.AT_AUTS, Value: auts}

	respPkt := &eap.EAPPacket{
		Code:       eap.CodeResponse,
		Identifier: id,
		Type:       eap.TypeAKA,
		Subtype:    eap.SubtypeSyncFailure,
		Data:       atAuts.Encode(), // 只需要 AUTS
	}

	eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: respPkt.Encode()}
	return []ikev2.Payload{eapPayload}, nil
}

func (s *Session) sendIKEAuthEAP(payloads []ikev2.Payload) error {
	// 包装载荷在 SK 中
	data, err := s.encryptAndWrap(payloads, ikev2.IKE_AUTH, false)
	if err != nil {
		return err
	}
	return s.socket.SendIKE(data)
}

func (s *Session) sendIKEAuthFinal() error {
	payloads, err := s.buildIKEAuthFinalPayloads()
	if err != nil {
		return err
	}

	data, err := s.encryptAndWrap(payloads, ikev2.IKE_AUTH, false)
	if err != nil {
		return err
	}

	return s.socket.SendIKE(data)
}

func (s *Session) buildIKEAuthFinalPayloads() ([]ikev2.Payload, error) {
	// Message 6: SK { AUTH }
	// AUTH = prf( prf(MSK, "Key Pad for IKEv2"), <SignedOctets> )
	// SignedOctets = RealMessage1 | NonceR_Data | prf(SK_pi, IDi_Body)

	if len(s.MSK) == 0 {
		return nil, errors.New("MSK 不可用作 AUTH")
	}

	// 1. 计算 Auth Key
	keyPad := []byte("Key Pad for IKEv2")
	prf := s.PRFAlg
	if prf == nil {
		return nil, errors.New("PRF 不可用")
	}

	authKey := prf.Compute(s.MSK, keyPad)

	// 2. 计算签名八位字节
	// 2a. RealMessage1 (IKE_SA_INIT 请求)
	// 我们把它存储在 s.msgBuffer 了吗？
	// 确保 s.msgBuffer 正是发送的内容。
	if len(s.msgBuffer) == 0 {
		return nil, errors.New("SA_INIT 请求未存储")
	}

	// 2b. NonceR
	if len(s.nr) == 0 {
		return nil, errors.New("NonceR 不可用")
	}

	// 2c. prf(SK_pi, IDi_Body)
	// 重建 IDi Body
	nai := s.currentIKEIdentity()

	// ID 载荷主体: IDType(1 byte) + Reserved(3 bytes) + IDData
	// IDType = ID_RFC822_ADDR (3)
	idiBody := make([]byte, 4+len(nai))
	idiBody[0] = ikev2.ID_RFC822_ADDR
	copy(idiBody[4:], []byte(nai))

	idHash := prf.Compute(s.Keys.SK_pi, idiBody)

	// 组合八位字节签名
	signedOctets := make([]byte, 0, len(s.msgBuffer)+len(s.nr)+len(idHash))
	signedOctets = append(signedOctets, s.msgBuffer...)
	signedOctets = append(signedOctets, s.nr...)
	signedOctets = append(signedOctets, idHash...)
	authData := prf.Compute(authKey, signedOctets)

	// 3. 构造 AUTH 载荷
	authPayload := &ikev2.EncryptedPayloadAuth{
		AuthMethod: ikev2.AuthMethodSharedKey, // 2 = Shared Key MIC
		AuthData:   authData,
	}
	return []ikev2.Payload{authPayload}, nil
}

func (s *Session) handleIKEAuthFinalResp(data []byte) error {
	_, payloads, err := s.decryptAndParse(data)
	if err != nil {
		return fmt.Errorf("解析 IKE_AUTH 最终响应失败: %v", err)
	}

	var saPayload *ikev2.EncryptedPayloadSA
	var cpPayload *ikev2.EncryptedPayloadCP
	var tsiPayload *ikev2.EncryptedPayloadTS
	var tsrPayload *ikev2.EncryptedPayloadTS
	var kePayload *ikev2.EncryptedPayloadKE
	for _, pl := range payloads {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadSA:
			saPayload = p
		case *ikev2.EncryptedPayloadKE:
			kePayload = p
		case *ikev2.EncryptedPayloadCP:
			cpPayload = p
		case *ikev2.EncryptedPayloadTS:
			if p.IsInitiator {
				tsiPayload = p
			} else {
				tsrPayload = p
			}
		case *ikev2.EncryptedPayloadNotify:
			if p.NotifyType < 16384 {
				return fmt.Errorf("IKE_AUTH 返回错误通知: type=%d proto=%d spi=%x data=%x", p.NotifyType, p.ProtocolID, p.SPI, p.NotifyData)
			}
			// 打印所有收到的状态类型 Notify，便于调试
			s.Logger.Debug("IKE_AUTH 收到状态 Notify",
				logger.Int("type", int(p.NotifyType)),
				logger.Int("dataLen", len(p.NotifyData)),
				logger.String("dataHex", fmt.Sprintf("%x", p.NotifyData)))
			// RFC 4478: AUTH_LIFETIME — ePDG 通告 IKE SA 最大生存时间（秒）
			if p.NotifyType == ikev2.AUTH_LIFETIME && len(p.NotifyData) >= 4 {
				lifetime := binary.BigEndian.Uint32(p.NotifyData[:4])
				s.authLifetime = lifetime
				s.Logger.Info("ePDG 通告 AUTH_LIFETIME",
					logger.Uint32("seconds", lifetime),
					logger.String("duration", (time.Duration(lifetime)*time.Second).String()))
			}
			// RFC 5685: REDIRECT
			if p.NotifyType == ikev2.REDIRECT {
				addr, err := ParseRedirectData(p.NotifyData)
				if err != nil {
					s.Logger.Warn("解析 REDIRECT 数据失败", logger.Err(err))
				} else {
					return &RedirectError{NewAddr: addr}
				}
			}
			// RFC 4555: MOBIKE_SUPPORTED
			if p.NotifyType == ikev2.MOBIKE_SUPPORTED {
				s.mobikeSupported = true
				s.Logger.Info("ePDG 支持 MOBIKE")
			}
			// RFC 5723: Session Resumption
			if p.NotifyType == ikev2.TICKET_OPAQUE && len(p.NotifyData) > 0 {
				s.resumeTicket = make([]byte, len(p.NotifyData))
				copy(s.resumeTicket, p.NotifyData)
				if s.Keys != nil && len(s.Keys.SK_d) > 0 {
					s.resumeOldSKd = make([]byte, len(s.Keys.SK_d))
					copy(s.resumeOldSKd, s.Keys.SK_d)
					s.Logger.Info("成功提取到会话恢复车票", logger.Int("ticketLen", len(s.resumeTicket)))
					if s.cfg.OnTicketUpdate != nil {
						s.cfg.OnTicketUpdate(s.resumeTicket, s.resumeOldSKd)
					}
				}
			}
		}
	}

	if saPayload == nil || len(saPayload.Proposals) == 0 {
		return errors.New("IKE_AUTH 最终响应缺少 Child SA")
	}

	respProp := saPayload.Proposals[0]
	if len(respProp.SPI) < 4 {
		return errors.New("IKE_AUTH 最终响应的 Child SA SPI 缺失")
	}
	remoteSPI := binary.BigEndian.Uint32(respProp.SPI[:4])

	var encrID uint16
	var encrKeyLenBits int
	var integID uint16
	var dhID uint16
	for _, t := range respProp.Transforms {
		if t.Type == ikev2.TransformTypeEncr {
			encrID = uint16(t.ID)
			for _, a := range t.Attributes {
				if a.Type == ikev2.AttributeKeyLength {
					encrKeyLenBits = int(a.Val)
				}
			}
		}
		if t.Type == ikev2.TransformTypeInteg {
			integID = uint16(t.ID)
		}
		if t.Type == ikev2.TransformTypeDH {
			dhID = uint16(t.ID)
		}
		// ESN Transform: ID=1 表示使用 ESN，ID=0 表示不使用
		if t.Type == ikev2.TransformTypeESN && t.ID == 1 {
			s.childESN = true
			s.Logger.Info("ePDG 选择了 ESN (扩展序列号)")
		}
	}
	if encrID == 0 {
		return errors.New("IKE_AUTH 最终响应缺少加密算法选择")
	}

	s.Logger.Info("ePDG_SA_AUTH: IPsec ESP (Child SA) 算法协商成功",
		logger.String("encr", ikev2.EncrToString(encrID)),
		logger.String("integ", ikev2.IntegToString(integID)),
		logger.Bool("esn", s.childESN),
	)

	childEnc, err := crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	if err != nil {
		return fmt.Errorf("不支持的 Child SA 加密算法: %d", encrID)
	}

	isAEAD := encrID == uint16(ikev2.ENCR_AES_GCM_16) || encrID == uint16(ikev2.ENCR_AES_GCM_12) || encrID == uint16(ikev2.ENCR_AES_GCM_8)
	encKeyLen := childEnc.KeySize()
	saltLen := 0
	integKeyLen := 0
	var integAlg crypto.IntegrityAlgorithm
	if isAEAD {
		saltLen = 4
	} else {
		integAlg, err = crypto.GetIntegrityAlgorithm(integID)
		if err != nil {
			return fmt.Errorf("不支持的 Child SA 完整性算法: %d", integID)
		}
		integKeyLen = integAlg.KeySize()
	}
	keyMatLen := 2 * (encKeyLen + saltLen + integKeyLen)

	seed := make([]byte, 0, len(s.ni)+len(s.nr))
	seed = append(seed, s.ni...)
	seed = append(seed, s.nr...)
	if dhID != 0 {
		if s.childDH == nil || kePayload == nil || len(kePayload.KEData) == 0 {
			return errors.New("Child SA 需要 PFS，但缺少 KE 载荷")
		}
		if _, err := s.childDH.ComputeSharedSecret(kePayload.KEData); err != nil {
			return fmt.Errorf("Child SA DH 计算失败: %v", err)
		}
		seed = append(seed, s.childDH.SharedKey...)
	}

	keyMat, err := crypto.PrfPlus(s.PRFAlg, s.Keys.SK_d, seed, keyMatLen)
	if err != nil {
		return err
	}

	cursor := 0
	outEncKey := keyMat[cursor : cursor+encKeyLen+saltLen]
	cursor += encKeyLen + saltLen
	outIntegKey := []byte(nil)
	if !isAEAD {
		outIntegKey = keyMat[cursor : cursor+integKeyLen]
		cursor += integKeyLen
	}
	inEncKey := keyMat[cursor : cursor+encKeyLen+saltLen]
	cursor += encKeyLen + saltLen
	inIntegKey := []byte(nil)
	if !isAEAD {
		inIntegKey = keyMat[cursor : cursor+integKeyLen]
	}

	if s.childSPI == 0 {
		return errors.New("本端 Child SA SPI 未初始化")
	}

	if isAEAD {
		s.ChildSAOut = ipsec.NewSecurityAssociation(remoteSPI, childEnc, outEncKey, nil)
		s.ChildSAOut.RemoteSPI = s.childSPI

		s.ChildSAIn = ipsec.NewSecurityAssociation(s.childSPI, childEnc, inEncKey, nil)
		s.ChildSAIn.RemoteSPI = remoteSPI
	} else {
		s.ChildSAOut = ipsec.NewSecurityAssociationCBC(remoteSPI, childEnc, outEncKey, integAlg, outIntegKey)
		s.ChildSAOut.RemoteSPI = s.childSPI

		s.ChildSAIn = ipsec.NewSecurityAssociationCBC(s.childSPI, childEnc, inEncKey, integAlg, inIntegKey)
		s.ChildSAIn.RemoteSPI = remoteSPI
	}
	if s.ChildSAsIn != nil {
		s.ChildSAsIn[s.childSPI] = s.ChildSAIn
	}

	// 保存 Child SA 算法 ID (供 XFRM 模式使用)
	s.childEncrID = encrID
	s.childIntegID = integID
	s.childEncrKeyLenBits = encrKeyLenBits

	if s.ws != nil {
		s.ws.LogChildSA(s.childSPI, remoteSPI, s.cfg.LocalAddr, s.cfg.EpDGAddr, inEncKey, outEncKey, encrID)
	}

	if cpPayload != nil {
		if cpPayload.Attributes != nil {
			types := make([]int, 0, len(cpPayload.Attributes))
			for _, a := range cpPayload.Attributes {
				if a == nil {
					continue
				}
				types = append(types, int(a.Type))
			}
			s.Logger.Debug("CP 属性类型", logger.Any("types", types))
		}
		s.cpConfig = ikev2.ParseCPConfig(cpPayload)
		if s.cpConfig != nil {
			toStrings := func(ips []net.IP) []string {
				out := make([]string, 0, len(ips))
				for _, ip := range ips {
					if ip == nil {
						continue
					}
					out = append(out, ip.String())
				}
				return out
			}
			ipv4 := ""
			if len(s.cpConfig.IPv4Addresses) > 0 && s.cpConfig.IPv4Addresses[0] != nil {
				ipv4 = s.cpConfig.IPv4Addresses[0].String()
			}
			ipv6 := ""
			if len(s.cpConfig.IPv6Addresses) > 0 && s.cpConfig.IPv6Addresses[0] != nil {
				ipv6 = s.cpConfig.IPv6Addresses[0].String()
			}
			s.Logger.Info("CP 配置已下发",
				logger.String("ipv4", ipv4),
				logger.String("ipv6", ipv6),
				logger.Int("dns_v4", len(s.cpConfig.IPv4DNS)),
				logger.Int("dns_v6", len(s.cpConfig.IPv6DNS)),
				logger.Int("pcscf_v4", len(s.cpConfig.IPv4PCSCF)),
				logger.Int("pcscf_v6", len(s.cpConfig.IPv6PCSCF)),
				logger.Any("pcscf_v4_ips", toStrings(s.cpConfig.IPv4PCSCF)),
				logger.Any("pcscf_v6_ips", toStrings(s.cpConfig.IPv6PCSCF)),
			)
		}
	}
	if tsiPayload != nil {
		s.tsi = tsiPayload.TrafficSelectors
	}
	if tsrPayload != nil {
		s.tsr = tsrPayload.TrafficSelectors
	}
	if len(s.tsr) > 0 && s.ChildSAOut != nil {
		s.childOutPolicies = append(s.childOutPolicies, childOutPolicy{saOut: s.ChildSAOut, tsr: s.tsr})
	}

	s.Logger.Info("Child SA 已建立", logger.Uint32("localSPI", s.childSPI), logger.Uint32("remoteSPI", remoteSPI))
	return nil
}

// prf256Plus 实现 RFC 5448 §3.4 定义的 PRF+ 密钥扩展算法 (基于 HMAC-SHA-256)。
// 输出 outLen 字节的密钥材料: T1 = HMAC-SHA256(key, 0x01) , T2 = HMAC-SHA256(key, T1 || 0x02) , ...
func prf256Plus(key []byte, outLen int) []byte {
	var result []byte
	var prev []byte
	for i := byte(1); len(result) < outLen; i++ {
		h := hmac.New(sha256.New, key)
		h.Write(prev)
		h.Write([]byte{i})
		prev = h.Sum(nil)
		result = append(result, prev...)
	}
	return result[:outLen]
}

// verifyEAPAKAPrimeMAC 校验 EAP-AKA' 报文中的 AT_MAC (使用 HMAC-SHA256-128，取前 16 字节)。
// eapRaw: 原始的完整 EAP 报文 (包含 header)
// attrData: EAP-AKA 数据域（用于定位 AT_MAC 占位符）
// kAut: 32 字节的 K_aut 密钥
// recvMac: 从 AT_MAC 属性中提取的 16 字节签名
func verifyEAPAKAPrimeMAC(eapRaw []byte, attrData []byte, kAut []byte, recvMac []byte) error {
	// 与 4G AKA 的 verifyEAPAKAMAC 逻辑完全相同，唯一不同是用 sha256.New 代替 sha1.New
	eapCopy := make([]byte, len(eapRaw))
	copy(eapCopy, eapRaw)

	// 寻找并清零 AT_MAC 的值域（Header 偏移 8 字节后的 attrData 中）
	for i := 0; i < len(attrData)-3; {
		attrType := attrData[i]
		attrLen := int(attrData[i+1]) * 4
		if attrLen < 4 {
			break
		}
		if attrType == eap.AT_MAC {
			// 在 eapCopy 中对应的位置清零 MAC 值 (跳过 2 字节保留域 + 16 字节 MAC)
			macStart := 8 + i + 4 // EAP header(8) + attr offset + Type(1)+Len(1)+Reserved(2)
			if macStart+16 <= len(eapCopy) {
				for j := 0; j < 16; j++ {
					eapCopy[macStart+j] = 0
				}
			}
			break
		}
		i += attrLen
	}

	h := hmac.New(sha256.New, kAut)
	h.Write(eapCopy)
	calcMac := h.Sum(nil)[:16] // HMAC-SHA256-128: 取前 16 字节

	if !hmac.Equal(calcMac, recvMac) {
		return fmt.Errorf("AKA' MAC mismatch: calc=%x recv=%x", calcMac, recvMac)
	}
	return nil
}
