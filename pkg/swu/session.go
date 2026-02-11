package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/iniwex5/swu-go/pkg/crypto"
	"github.com/iniwex5/swu-go/pkg/driver"
	"github.com/iniwex5/swu-go/pkg/ikev2"
	"github.com/iniwex5/swu-go/pkg/ipsec"
	"github.com/iniwex5/swu-go/pkg/logger"
)

type Session struct {
	cfg    *Config
	socket Transport
	tun    TUN
	net    NetTools

	// IKE SA 状态
	SPIi     uint64
	SPIr     uint64
	EncAlg   crypto.Encrypter
	IntegAlg crypto.IntegrityAlgorithm
	PRFAlg   crypto.PRF
	DH       *crypto.DiffieHellman

	Keys *ikev2.IKESAKeys

	SequenceNumber uint32 // IKE 消息 ID

	ikeEncrID  uint16
	ikeIntegID uint16
	ikeIsAEAD  bool

	// Child SA 状态 (目前仅支持一对)
	ChildSAIn  *ipsec.SecurityAssociation
	ChildSAOut *ipsec.SecurityAssociation
	ChildSAsIn map[uint32]*ipsec.SecurityAssociation

	childSPI uint32
	childDH  *crypto.DiffieHellman

	natKeepaliveStarted bool

	cpConfig *ikev2.CPConfig
	tsi      []*ikev2.TrafficSelector
	tsr      []*ikev2.TrafficSelector
	netUndos []func() error

	childOutPolicies []childOutPolicy

	ikeMu           sync.Mutex
	ikeStarted      bool
	ikeWaiters      map[ikeWaitKey]chan []byte
	ikePending      map[ikeWaitKey][]byte
	ikeControlAlive bool

	// 临时状态
	ni        []byte // Nonce Init
	nr        []byte // Nonce Resp
	msgBuffer []byte // 上次发送的消息用于重传 (尚未使用的)
	MSK       []byte // 来自 EAP 的主会话密钥

	lastEncryptedMsg   []byte
	lastEncryptedMsgID uint32

	// COOKIE 处理
	cookie     []byte // ePDG 返回的 COOKIE
	sendCookie bool   // 标记是否需要发送 COOKIE

	// 生命周期管理
	ctx    context.Context
	cancel context.CancelFunc

	retryCtx *RetryContext

	ws *WiresharkDebugger
}

type ikeWaitKey struct {
	exchangeType ikev2.ExchangeType
	msgID        uint32
}

type childOutPolicy struct {
	saOut *ipsec.SecurityAssociation
	tsr   []*ikev2.TrafficSelector
}

func NewSession(cfg *Config) *Session {
	// 生成随机 SPIi
	spiBytes, _ := crypto.RandomBytes(8)
	spii := binary.BigEndian.Uint64(spiBytes)

	netTools := cfg.NetTools
	if netTools == nil {
		netTools = driver.NewNetTools()
	}

	return &Session{
		cfg:            cfg,
		net:            netTools,
		SPIi:           spii,
		SequenceNumber: 0,
		ChildSAsIn:     make(map[uint32]*ipsec.SecurityAssociation),
		ikeWaiters:     make(map[ikeWaitKey]chan []byte),
		ikePending:     make(map[ikeWaitKey][]byte),
	}
}

// Connect 连接到 ePDG，使用提供的 context 进行生命周期管理
func (s *Session) Connect(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	handshakeStart := time.Now()
	var err error
	s.retryCtx = NewRetryContext(s.ctx, nil)

	// 1. 设置网络 (Socket)
	localPort := s.cfg.LocalPort
	localBind := fmt.Sprintf("%s:%d", s.cfg.LocalAddr, localPort)
	remotePort := s.cfg.EpDGPort
	if remotePort == 0 {
		remotePort = 500
	}
	remoteAddr := fmt.Sprintf("%s:%d", s.cfg.EpDGAddr, remotePort)

	if s.cfg.TransportFactory != nil {
		s.socket, err = s.cfg.TransportFactory(localBind, remoteAddr)
	} else {
		s.socket, err = ipsec.NewSocketManager(localBind, remoteAddr, s.cfg.DNSServer)
		if err != nil && localPort != 0 {
			localBind = fmt.Sprintf("%s:%d", s.cfg.LocalAddr, 0)
			s.socket, err = ipsec.NewSocketManager(localBind, remoteAddr, s.cfg.DNSServer)
		}
	}
	if err != nil {
		return fmt.Errorf("failed to bind socket: %v", err)
	}
	s.socket.Start()
	defer s.socket.Stop()

	if sm, ok := s.socket.(interface {
		LocalAddrString() string
		RemoteAddrString() string
	}); ok {
		logger.Info("正在连接到 ePDG",
			logger.String("remote", sm.RemoteAddrString()),
			logger.String("local", sm.LocalAddrString()))
	} else {
		logger.Info("正在连接到 ePDG", logger.String("addr", s.cfg.EpDGAddr))
	}

	go s.logSessionStats(60 * time.Second)

	// 2. IKE_SA_INIT
	for {
		reqData, err := s.buildIKESAInitPacket()
		if err != nil {
			return err
		}

		respData, err := s.retryCtx.SendWithRetry(
			s.socket.SendIKE,
			s.receiveIKEWithTimeout,
			reqData,
		)
		if err != nil {
			return err
		}

		if err := s.handleIKESAInitResp(respData); err != nil {
			if errors.Is(err, ErrCookieRequired) {
				continue
			}
			return err
		}
		break
	}

	logger.Info("IKE_SA_INIT 完成，密钥已生成")
	s.SequenceNumber = 1

	s.ws, err = NewWiresharkDebugger(s.cfg.EnableWiresharkKeyLog, s.cfg.WiresharkKeyLogPath)
	if err != nil {
		return err
	}
	if s.ws != nil {
		defer s.ws.Close()
		s.ws.LogIKESAKeys(s.SPIi, s.SPIr, s.Keys.SK_ei, s.Keys.SK_er, s.Keys.SK_ai, s.Keys.SK_ar, s.ikeEncrID, s.ikeIntegID)
	}

	// 3. IKE_AUTH
	// 警告: IKE_AUTH 通常发送 EAP 请求？或者 EAP 在 IKE_AUTH 响应内部开始？
	// RFC 7296 1.2:
	// Init -> SA, KE, Ni, N(NAT_DETECTION_*)
	// Resp -> SA, KE, Nr, N(NAT_DETECTION_*), [CERTREQ]
	// Init -> SK { IDi, [CERT+], [CERTREQ+], [IDr], AUTH, SAi2, TSi, TSr }
	// 等等，对于 EAP-AKA:
	// Init -> SK { IDi, SAi2, TSi, TSr, N(EAP_ONLY) }  (还没有 AUTH，因为我们要进行 EAP)
	// Resp -> SK { IDr, AUTH, EAP(Request) }

	payloads, err := s.buildIKEAuthInitPayloads()
	if err != nil {
		return err
	}

	respData, err := s.sendEncryptedWithRetry(payloads, ikev2.IKE_AUTH)
	if err != nil {
		return err
	}

	// EAP 本地循环
	for {
		msgID, payloads, err := s.decryptAndParse(respData)
		if err != nil {
			return err
		}
		_ = msgID // 检查 ID 是否匹配 SequenceNumber？

		// 处理载荷
		var eapPayload *ikev2.EncryptedPayloadEAP
		// var authPayload *ikev2.EncryptedPayloadAuth

		for _, p := range payloads {
			if e, ok := p.(*ikev2.EncryptedPayloadEAP); ok {
				eapPayload = e
			}
			// 检查 AUTH (成功)
			if _, ok := p.(*ikev2.EncryptedPayloadAuth); ok {
				// EAP Success 通常随服务器的 AUTH 一起到来
				logger.Info("收到 AUTH 载荷")
			}
			// 检查 CP (配置)
			if _, ok := p.(*ikev2.EncryptedPayloadCP); ok {
				logger.Info("收到配置载荷")
				// 解析 IP 和 DNS
			}
		}

		if eapPayload != nil {
			// 处理 EAP
			respEAP, err := s.handleEAP(eapPayload.EAPMessage)
			if err != nil {
				return err
			}

			// 发送 EAP 响应 (IKE_AUTH 继续)
			if respEAP == nil {
				break
			}
			respData, err = s.sendEncryptedWithRetry(respEAP, ikev2.IKE_AUTH)
			if err != nil {
				return err
			}
			continue
		}

		if len(s.MSK) == 0 {
			var types []int
			var notifies []uint16
			for _, pl := range payloads {
				types = append(types, int(pl.Type()))
				if n, ok := pl.(*ikev2.EncryptedPayloadNotify); ok {
					notifies = append(notifies, n.NotifyType)
				}
			}
			if len(notifies) > 0 {
				return fmt.Errorf("对端未返回 EAP 载荷(payloadTypes=%v notifyTypes=%v)，无法继续 EAP-AKA", types, notifies)
			}
			return fmt.Errorf("对端未返回 EAP 载荷(payloadTypes=%v)，无法继续 EAP-AKA", types)
		}

		logger.Info("握手循环完成")
		break
	}

	if err := s.handleIKEAuthFinalResp(respData); err != nil {
		logger.Info("EAP 成功响应未完成 CHILD_SA，尝试发送最终 AUTH")
		finalPayloads, err := s.buildIKEAuthFinalPayloads()
		if err != nil {
			return fmt.Errorf("failed to build final AUTH: %v", err)
		}
		respData, err = s.sendEncryptedWithRetry(finalPayloads, ikev2.IKE_AUTH)
		if err != nil {
			return fmt.Errorf("failed to send final AUTH: %v", err)
		}
		if err := s.handleIKEAuthFinalResp(respData); err != nil {
			return err
		}
	}

	logger.Info("会话已建立", logger.Duration("handshake", time.Since(handshakeStart)))

	// 4. 设置 IPSec 数据平面
	if s.cfg.EnableDriver {
		if err := s.setupDataPlane(); err != nil {
			return err
		}

		// 启动数据循环
		s.startDataPlaneLoop()
	}

	s.startIKEControlLoop()

	// 等待 context 取消 (优雅关闭)
	<-s.ctx.Done()
	logger.Info("收到关闭信号，正在清理")

	// 发送 IKE SA Delete 通知
	if err := s.sendDeleteIKE(); err != nil {
		logger.Warn("发送 Delete 通知失败", logger.Err(err))
	}

	s.cleanupNetworkConfig()

	return s.ctx.Err()
}

func (s *Session) cleanupNetworkConfig() {
	for i := len(s.netUndos) - 1; i >= 0; i-- {
		if err := s.netUndos[i](); err != nil {
			logger.Warn("回滚网络配置失败", logger.Err(err))
		}
	}
	s.netUndos = nil
}

func (s *Session) logSessionStats(interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			stats := s.retryCtx.Stats()
			logger.Debug("会话统计",
				logger.Uint64("spii", s.SPIi),
				logger.Uint64("spir", s.SPIr),
				logger.Uint64("attempts", stats.TotalAttempts),
				logger.Uint64("timeouts", stats.TotalTimeouts),
				logger.Uint64("success", stats.TotalSuccess),
				logger.Uint64("failures", stats.TotalFailures),
			)

			if sm, ok := s.socket.(*ipsec.SocketManager); ok {
				sockStats := sm.Stats()
				logger.Debug("Socket 统计",
					logger.Uint64("spii", s.SPIi),
					logger.Uint64("spir", s.SPIr),
					logger.Uint64("ikeRecv", sockStats.ReceivedIKE),
					logger.Uint64("espRecv", sockStats.ReceivedESP),
					logger.Uint64("ikeDrop", sockStats.DroppedIKE),
					logger.Uint64("espDrop", sockStats.DroppedESP),
				)
			}
		}
	}
}

func (s *Session) startNATKeepalive(interval time.Duration) {
	if s.natKeepaliveStarted || interval <= 0 {
		return
	}
	s.natKeepaliveStarted = true

	sender, ok := s.socket.(interface{ SendNATKeepalive() error })
	if !ok {
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				if err := sender.SendNATKeepalive(); err != nil {
					logger.Debug("NAT keepalive 发送失败", logger.Err(err))
				}
			}
		}
	}()
}

// Shutdown 优雅关闭会话
func (s *Session) Shutdown() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Session) setupDataPlane() error {
	// 创建 TUN
	tunName := s.cfg.TUNName

	var (
		tun TUN
		err error
	)
	if s.cfg.TUNFactory != nil {
		tun, err = s.cfg.TUNFactory(tunName)
	} else {
		tun, err = driver.NewTUNDevice(tunName)
	}
	if err != nil {
		return err
	}
	s.tun = tun

	if nt, ok := s.net.(*driver.NetTools); ok {
		tx := nt.Begin()
		if err := tx.SetLinkUp(s.tun.DeviceName()); err != nil {
			s.tun.Close()
			s.tun = nil
			return err
		}
		mtu := s.cfg.TUNMTU
		if mtu == 0 {
			mtu = 1200
		}
		if mtu > 0 && s.cpConfig != nil && len(s.cpConfig.IPv6Addresses) > 0 && mtu < 1280 {
			mtu = 1280
		}
		if mtu > 0 {
			if err := tx.SetMTU(s.tun.DeviceName(), mtu); err != nil {
				logger.Warn("设置 TUN MTU 失败，将继续", logger.String("iface", s.tun.DeviceName()), logger.Int("mtu", mtu), logger.Err(err))
			}
		}
		tx.Commit()
	} else {
		if err := s.net.SetLinkUp(s.tun.DeviceName()); err != nil {
			s.tun.Close()
			s.tun = nil
			return err
		}
		mtu := s.cfg.TUNMTU
		if mtu == 0 {
			mtu = 1200
		}
		if mtu > 0 && s.cpConfig != nil && len(s.cpConfig.IPv6Addresses) > 0 && mtu < 1280 {
			mtu = 1280
		}
		if mtu > 0 {
			if err := s.net.SetMTU(s.tun.DeviceName(), mtu); err != nil {
				logger.Warn("设置 TUN MTU 失败，将继续", logger.String("iface", s.tun.DeviceName()), logger.Int("mtu", mtu), logger.Err(err))
			}
		}
	}
	if err := s.applyNetworkConfigOnTUN(s.tun.DeviceName()); err != nil {
		s.tun.Close()
		s.tun = nil
		s.cleanupNetworkConfig()
		return err
	}

	return nil
}

type netToolsDeleter interface {
	DelAddress(iface string, cidr string) error
	DelRoute(cidr string, gw string, iface string) error
	DelAddress6(iface string, cidr string) error
	DelRoute6(cidr string, gw string, iface string) error
}

func (s *Session) applyNetworkConfigOnTUN(iface string) error {
	deleter, _ := s.net.(netToolsDeleter)

	if s.cpConfig != nil {
		if len(s.cpConfig.IPv4Addresses) > 0 {
			ip := s.cpConfig.IPv4Addresses[0].To4()
			if ip != nil {
				cidr := fmt.Sprintf("%s/32", ip.String())
				if err := s.net.AddAddress(iface, cidr); err != nil {
					return err
				}
				if deleter != nil {
					s.netUndos = append(s.netUndos, func() error { return deleter.DelAddress(iface, cidr) })
				}
			}
		}
		if len(s.cpConfig.IPv6Addresses) > 0 {
			ip := s.cpConfig.IPv6Addresses[0].To16()
			if ip != nil {
				cidr := fmt.Sprintf("%s/128", ip.String())
				if err := s.net.AddAddress6(iface, cidr); err != nil {
					return err
				}
				if deleter != nil {
					s.netUndos = append(s.netUndos, func() error { return deleter.DelAddress6(iface, cidr) })
				}
			}
		}
	}

	var routes []string
	var routes6 []string
	if s.cpConfig != nil {
		for _, ip := range s.cpConfig.IPv4PCSCF {
			if v4 := ip.To4(); v4 != nil {
				routes = append(routes, fmt.Sprintf("%s/32", v4.String()))
			}
		}
		for _, ip := range s.cpConfig.IPv6PCSCF {
			if v6 := ip.To16(); v6 != nil {
				routes6 = append(routes6, fmt.Sprintf("%s/128", v6.String()))
			}
		}
	}

	for _, ts := range s.tsr {
		if ts.TSType != ikev2.TS_IPV4_ADDR_RANGE {
			continue
		}
		if isFullIPv4Range(ts) {
			continue
		}
		start := net.IP(ts.StartAddr)
		end := net.IP(ts.EndAddr)
		cidrs, err := ipv4RangeToCIDRs(start, end)
		if err != nil {
			continue
		}
		routes = append(routes, cidrs...)
	}

	for _, cidr := range routes {
		if err := s.net.AddRoute(cidr, "", iface); err != nil {
			return err
		}
		if deleter != nil {
			c := cidr
			s.netUndos = append(s.netUndos, func() error { return deleter.DelRoute(c, "", iface) })
		}
	}
	for _, cidr := range routes6 {
		if err := s.net.AddRoute6(cidr, "", iface); err != nil {
			return err
		}
		if deleter != nil {
			c := cidr
			s.netUndos = append(s.netUndos, func() error { return deleter.DelRoute6(c, "", iface) })
		}
	}
	return nil
}

func (s *Session) startDataPlaneLoop() {
	logger.Info("ESP 数据平面循环启动", logger.String("tun", s.tun.DeviceName()))

	// TUN -> ESP
	go func() {
		logger.Info("TUN->ESP goroutine 启动")
		buf := make([]byte, 2000)
		var tunReadCount, espSendCount, saDropCount uint64
		for {
			n, err := s.tun.Read(buf)
			if err != nil {
				logger.Info("TUN 读取结束", logger.Err(err))
				break
			}
			tunReadCount++
			packet := buf[:n]

			// 解析 IP 头提取目标地址用于调试
			var dstIP string
			var proto uint8
			if len(packet) > 0 {
				ver := packet[0] >> 4
				if ver == 4 && len(packet) >= 20 {
					dstIP = net.IP(packet[16:20]).String()
					proto = packet[9]
				} else if ver == 6 && len(packet) >= 40 {
					dstIP = net.IP(packet[24:40]).String()
					proto = packet[6]
				}
			}

			saOut := s.selectOutgoingSA(packet)
			if saOut == nil {
				saDropCount++
				if saDropCount <= 5 || saDropCount%100 == 0 {
					logger.Warn("ESP 出站 SA 为空，丢弃数据包",
						logger.Uint64("dropCount", saDropCount),
						logger.String("dstIP", dstIP),
						logger.Int("proto", int(proto)),
						logger.Int("len", n))
				}
				continue
			}

			espPacket, err := ipsec.Encapsulate(packet, saOut)
			if err != nil {
				logger.Warn("ESP 封装错误", logger.Err(err), logger.String("dstIP", dstIP))
				continue
			}

			if err := s.socket.SendESP(espPacket); err != nil {
				logger.Warn("ESP 发送失败", logger.Err(err), logger.String("dstIP", dstIP))
				continue
			}

			espSendCount++
			if espSendCount <= 10 || espSendCount%100 == 0 {
				logger.Debug("ESP 已发送",
					logger.Uint64("count", espSendCount),
					logger.String("dstIP", dstIP),
					logger.Int("proto", int(proto)),
					logger.Int("plainLen", n),
					logger.Int("espLen", len(espPacket)),
					logger.Uint32("spi", saOut.SPI))
			}
		}
		logger.Info("TUN->ESP 循环退出", logger.Uint64("tunRead", tunReadCount), logger.Uint64("espSend", espSendCount), logger.Uint64("saDrop", saDropCount))
	}()

	// ESP -> TUN
	go func() {
		var espRecvCount, tunWriteCount uint64
		for espData := range s.socket.ESPPackets() {
			espRecvCount++

			var spi uint32
			if len(espData) >= 4 {
				spi = binary.BigEndian.Uint32(espData[0:4])
			}

			sa := s.ChildSAIn
			if len(espData) >= 4 && s.ChildSAsIn != nil {
				if hit, ok := s.ChildSAsIn[spi]; ok {
					sa = hit
				}
			}

			if sa == nil {
				logger.Warn("ESP 入站 SA 为空，丢弃数据包", logger.Uint32("spi", spi), logger.Int("len", len(espData)))
				continue
			}

			packet, err := ipsec.Decapsulate(espData, sa)
			if err != nil {
				logger.Warn("ESP 解封装错误", logger.Err(err), logger.Uint32("spi", spi), logger.Int("len", len(espData)))
				continue
			}

			// 解析源 IP 用于调试
			var srcIP string
			if len(packet) > 0 {
				ver := packet[0] >> 4
				if ver == 4 && len(packet) >= 20 {
					srcIP = net.IP(packet[12:16]).String()
				} else if ver == 6 && len(packet) >= 40 {
					srcIP = net.IP(packet[8:24]).String()
				}
			}

			if _, err := s.tun.Write(packet); err != nil {
				logger.Warn("TUN 写入失败", logger.Err(err), logger.String("srcIP", srcIP))
				continue
			}

			tunWriteCount++
			if tunWriteCount <= 10 || tunWriteCount%100 == 0 {
				logger.Debug("TUN 已写入",
					logger.Uint64("count", tunWriteCount),
					logger.String("srcIP", srcIP),
					logger.Int("len", len(packet)),
					logger.Uint32("spi", spi))
			}
		}
		logger.Info("ESP->TUN 循环退出", logger.Uint64("espRecv", espRecvCount), logger.Uint64("tunWrite", tunWriteCount))
	}()
}

func (s *Session) receiveIKEWithTimeout(timeout time.Duration) ([]byte, error) {
	return s.receiveIKEResponseWithTimeout(ikev2.IKE_SA_INIT, 0, timeout)
}

func (s *Session) receiveIKEResponseWithTimeout(exchangeType ikev2.ExchangeType, msgID uint32, timeout time.Duration) ([]byte, error) {
	s.ensureIKEDispatcher()

	key := ikeWaitKey{exchangeType: exchangeType, msgID: msgID}
	ch := make(chan []byte, 1)

	s.ikeMu.Lock()
	if pending, ok := s.ikePending[key]; ok {
		delete(s.ikePending, key)
		s.ikeMu.Unlock()
		return pending, nil
	}
	s.ikeWaiters[key] = ch
	s.ikeMu.Unlock()

	defer func() {
		s.ikeMu.Lock()
		if s.ikeWaiters[key] == ch {
			delete(s.ikeWaiters, key)
		}
		s.ikeMu.Unlock()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-timer.C:
		return nil, context.DeadlineExceeded
	case data := <-ch:
		return data, nil
	}
}

func (s *Session) sendEncryptedWithRetry(payloads []ikev2.Payload, exchangeType ikev2.ExchangeType) ([]byte, error) {
	if s.retryCtx == nil {
		return nil, errors.New("重传上下文未初始化")
	}
	packetData, err := s.encryptAndWrap(payloads, exchangeType, false)
	if err != nil {
		return nil, err
	}
	msgID := s.SequenceNumber - 1
	s.lastEncryptedMsg = packetData
	s.lastEncryptedMsgID = msgID
	logger.Debug("发送加密 IKE 消息",
		logger.Uint64("spii", s.SPIi),
		logger.Uint64("spir", s.SPIr),
		logger.Uint32("msgid", msgID),
		logger.Int("exchange", int(exchangeType)),
	)

	return s.retryCtx.SendWithRetry(
		s.socket.SendIKE,
		func(timeout time.Duration) ([]byte, error) {
			return s.receiveIKEResponseWithTimeout(exchangeType, msgID, timeout)
		},
		packetData,
	)
}
