package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"

	"sync"
	"time"

	"github.com/iniwex5/netlink"
	"github.com/iniwex5/netlink/nl"
	"github.com/iniwex5/swu-go/pkg/crypto"
	"github.com/iniwex5/swu-go/pkg/driver"
	"github.com/iniwex5/swu-go/pkg/ikev2"
	"github.com/iniwex5/swu-go/pkg/ipsec"
	"github.com/iniwex5/swu-go/pkg/logger"
	"go.uber.org/zap"
)

// SA 生命周期常量（秒）
const (
	ikeRekeyInterval   = 360 // 6 分钟：主动 IKE SA Rekey
	childRekeyInterval = 420 // 7 分钟：主动 Child SA Rekey（在 ePDG ~8 分钟 ESP SA 过期前）
	childRekeyJitter   = 30  // 最大 30 秒随机 jitter，避免多设备同时 Rekey
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

	childSPI            uint32
	childDH             *crypto.DiffieHellman
	childEncrID         uint16 // Child SA 加密算法 ID (用于 XFRM 映射)
	childIntegID        uint16 // Child SA 完整性算法 ID
	childEncrKeyLenBits int    // Child SA 加密密钥位数
	childESN            bool   // Child SA 是否使用 ESN (扩展序列号)

	natKeepaliveStarted bool

	cpConfig *ikev2.CPConfig
	tsi      []*ikev2.TrafficSelector
	tsr      []*ikev2.TrafficSelector
	netUndos []func() error
	xfrmMgr  *driver.XFRMManager // XFRMI 模式下的 XFRM 管理器
	done     chan struct{}       // 清理完成信号（Run() 返回前关闭）

	// XFRM SA 上下文（setupXFRMDataPlane 时缓存，rekey 时复用）
	xfrmLocalIP    net.IP
	xfrmRemoteIP   net.IP
	xfrmLocalPort  int
	xfrmRemotePort int
	xfrmIfID       int

	// 隧道断线回调（Hard Expire / DPD 连续失败时调用）
	OnSessionDown func()

	// Rekey 互斥锁（防止两个 SPI 的 expire 同时触发）
	rekeyMu sync.Mutex
	// 上次成功 Rekey 的时间（用于冷却期去重）
	lastRekeyTime time.Time
	// IKE SA Rekey 成功后通知 Timer 重置的 channel
	rekeyResetCh chan struct{}
	// Child SA Rekey 成功后通知 Timer 重置的 channel
	childRekeyResetCh chan struct{}

	// ePDG 通告的 IKE SA 最大生命周期（秒），通过 AUTH_LIFETIME Notify 获取
	// 0 表示 ePDG 未通告，使用默认的硬编码值
	authLifetime uint32

	childOutPolicies []childOutPolicy
	xfrmPolicies     []driver.XFRMSPConfig // 缓存所有 XFRM SP（MOBIKE 地址更新时使用）

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

	mobikeSupported        bool            // 对端是否支持 MOBIKE (RFC 4555)
	fragmentationSupported bool            // 对端是否支持 IKE Fragmentation (RFC 7383)
	fragmentBuf            *fragmentBuffer // IKE Fragmentation 接收缓冲区

	// 生命周期管理
	ctx           context.Context
	cancel        context.CancelFunc
	reauthTrigger chan struct{} // 触发 Reauth 的信号通道

	retryCtx *RetryContext

	ws *WiresharkDebugger

	Logger *zap.Logger
}

type ikeWaitKey struct {
	exchangeType ikev2.ExchangeType
	msgID        uint32
}

type childOutPolicy struct {
	saOut *ipsec.SecurityAssociation
	tsr   []*ikev2.TrafficSelector
	cfg   driver.XFRMSPConfig // SP 配置缓存（MOBIKE 地址更新时使用）
}

// RedirectError 表示 ePDG 要求重定向
type RedirectError struct {
	NewAddr string
}

func (e *RedirectError) Error() string {
	return fmt.Sprintf("ePDG requested redirect to: %s", e.NewAddr)
}

var ErrReauth = errors.New("reauthentication triggered")

func NewSession(cfg *Config, l *zap.Logger) *Session {
	if l == nil {
		l = logger.Get() // Fallback to global logger if nil provided
		l.Warn("NewSession received nil logger, falling back to global logger")
	}

	// 生成随机 SPIi
	spiBytes, _ := crypto.RandomBytes(8)
	spii := binary.BigEndian.Uint64(spiBytes)

	netTools := cfg.NetTools
	if netTools == nil {
		netTools = driver.NewNetTools()
	}

	return &Session{
		cfg:              cfg,
		Logger:           l,
		net:              netTools,
		SPIi:             spii,
		SequenceNumber:   0,
		ChildSAsIn:       make(map[uint32]*ipsec.SecurityAssociation),
		ikeWaiters:       make(map[ikeWaitKey]chan []byte),
		ikePending:       make(map[ikeWaitKey][]byte),
		childOutPolicies: make([]childOutPolicy, 0),
		done:             make(chan struct{}),
		reauthTrigger:    make(chan struct{}, 1),
		fragmentBuf:      newFragmentBuffer(),
	}
}

// Connect 连接到 ePDG，支持 REDIRECT 重连和 Reauthentication
func (s *Session) Connect(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	const maxRedirects = 3
	redirectCount := 0

	for {
		err := s.connectOnce()
		if err == nil {
			return nil
		}

		// 检查 Reauth 信号
		if errors.Is(err, ErrReauth) {
			s.Logger.Info("Reauthentication: 重新开始连接流程")
			// 重置 Redirect 计数，因为这是全新的连接尝试
			redirectCount = 0
			// 不关闭 Socket? connectOnce 已经负责清理了上一轮的资源
			// 但我们希望保留某些状态吗？不，Reauth 是全新的 IKE SA。
			continue
		}

		// 检查是否是重定向错误
		if redir, ok := err.(*RedirectError); ok {
			if redirectCount >= maxRedirects {
				return fmt.Errorf("exceeded max redirects (%d)", maxRedirects)
			}
			redirectCount++
			s.Logger.Info("收到 REDIRECT 请求，正在重连",
				logger.String("newAddr", redir.NewAddr),
				logger.Int("attempt", redirectCount))

			s.cfg.EpDGAddr = redir.NewAddr
			continue
		}
		return err
	}
}

// connectOnce 执行一次完整的 IKE 连接流程
func (s *Session) connectOnce() error {
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
		s.Logger.Debug("正在连接到 ePDG",
			logger.String("remote", sm.RemoteAddrString()),
			logger.String("local", sm.LocalAddrString()))
	} else {
		s.Logger.Debug("正在连接到 ePDG", logger.String("addr", s.cfg.EpDGAddr))
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

	s.Logger.Debug("IKE_SA_INIT 完成，密钥已生成")
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
				s.Logger.Debug("收到 AUTH 载荷")
			}
			// 检查 CP (配置)
			if _, ok := p.(*ikev2.EncryptedPayloadCP); ok {
				s.Logger.Debug("收到配置载荷")
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

		s.Logger.Debug("握手循环完成")
		break
	}

	if err := s.handleIKEAuthFinalResp(respData); err != nil {
		s.Logger.Debug("EAP 成功响应未完成 CHILD_SA，尝试发送最终 AUTH")
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

	s.Logger.Info("会话已建立", logger.Duration("handshake", time.Since(handshakeStart)))

	// 4. 设置 IPSec 数据平面
	// 强制启用 XFRMI 模式 (DEBUG FIX)
	s.cfg.EnableDriver = true
	s.cfg.DataplaneMode = "xfrmi"

	if s.cfg.EnableDriver {
		if s.cfg.DataplaneMode == "xfrmi" {
			// XFRMI 模式: 使用内核 XFRM offload
			if err := s.setupXFRMDataPlane(); err != nil {
				s.cleanupNetworkConfig()
				return err
			}
			// XFRMI 模式不需要用户空间数据循环，内核自动处理 ESP 加解密
		} else {
			// TUN 模式: 用户空间 ESP 加解密
			if err := s.setupDataPlane(); err != nil {
				return err
			}
			s.startDataPlaneLoop()
		}
	}

	s.startIKEControlLoop()

	// 计算 Rekey 间隔：如果 ePDG 通告了 AUTH_LIFETIME，动态调整
	ikeInterval := time.Duration(ikeRekeyInterval) * time.Second
	childInterval := time.Duration(childRekeyInterval) * time.Second
	if s.authLifetime > 0 {
		// IKE Rekey 间隔 = AUTH_LIFETIME 的 80%，在 ePDG 强制删除前完成
		ikeInterval = time.Duration(float64(s.authLifetime)*0.8) * time.Second
		// Child Rekey 间隔 = AUTH_LIFETIME 的 87.5%，在 IKE Rekey 前先刷新 ESP
		childInterval = time.Duration(float64(s.authLifetime)*0.875) * time.Second
		s.Logger.Info("根据 AUTH_LIFETIME 动态调整 Rekey 间隔",
			logger.Uint32("authLifetime", s.authLifetime),
			logger.Duration("ikeRekey", ikeInterval),
			logger.Duration("childRekey", childInterval))
	}

	// 启动 IKE SA 生命周期管理：定时触发 IKE SA Rekey
	s.startIKESARekeyTimer(ikeInterval)

	// 启动 Child SA 生命周期管理：定时触发 Child SA Rekey
	// 参考 strongSwan rekey_child_sa_job：在 ePDG ESP SA 过期前刷新
	s.startChildSARekeyTimer(childInterval)

	// 启动 Reauth Timer (如果配置了)
	if s.cfg.ReauthInterval > 0 {
		s.startIKEReauthTimer(time.Duration(s.cfg.ReauthInterval) * time.Second)
	}

	// 启动 XFRM SA Expire 内核事件监听（仅做日志+Hard Expire 处理）
	s.startXFRMExpireMonitor()

	// 等待 context 取消 (优雅关闭) 或 Reauth 触发
	select {
	case <-s.ctx.Done():
		s.Logger.Info("收到关闭信号，正在清理")
	case <-s.reauthTrigger:
		s.Logger.Info("触发 IKE Reauthentication，正在断开旧连接")
		// 发送 Delete 通知
		if err := s.sendDeleteIKE(); err != nil {
			s.Logger.Warn("发送 Delete 通知失败", logger.Err(err))
		}
		// 返回 ErrReauth 信号
		err = ErrReauth
	}

	if err != ErrReauth {
		// 仅在非 Reauth（正常关闭）时发送 Delete
		if err := s.sendDeleteIKE(); err != nil {
			s.Logger.Warn("发送 Delete 通知失败", logger.Err(err))
		}
	}

	s.cleanupNetworkConfig()
	close(s.done) // 通知外部清理已完成

	if err == ErrReauth {
		return err
	}
	return s.ctx.Err()
}

// Reauthenticate 触发完全重认证 (RFC 7296 §2.8.3)
// 实现 Break-Before-Make
func (s *Session) Reauthenticate() {
	select {
	case s.reauthTrigger <- struct{}{}:
	default:
	}
}

func (s *Session) startIKEReauthTimer(interval time.Duration) {
	s.Logger.Info("启动 IKE SA Reauth 定时器", logger.Duration("interval", interval))
	go func() {
		// 添加抖动 (0-10%)
		jitter := time.Duration(rand.Int63n(int64(interval / 10)))
		timer := time.NewTimer(interval + jitter)
		defer timer.Stop()

		for {
			select {
			case <-s.ctx.Done():
				return
			case <-timer.C:
				s.Reauthenticate()
				return
			}
		}
	}()
}

// WaitDone 阻塞等待 Session 清理完成（Run 返回前的 cleanup 执行完毕）
func (s *Session) WaitDone() {
	<-s.done
}

func (s *Session) cleanupNetworkConfig() {
	s.Logger.Debug("开始清理网络配置", logger.Int("count", len(s.netUndos)))
	for i := len(s.netUndos) - 1; i >= 0; i-- {
		s.Logger.Debug("执行清理操作", logger.Int("index", i))
		if err := s.netUndos[i](); err != nil {
			s.Logger.Warn("回滚网络配置失败", logger.Err(err))
		}
	}
	s.netUndos = nil
	s.Logger.Info("网络配置清理完成")
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
			// stats := s.retryCtx.Stats()
			// s.Logger.Debug("会话统计",
			// 	logger.Uint64("spii", s.SPIi),
			// 	logger.Uint64("spir", s.SPIr),
			// 	logger.Uint64("attempts", stats.TotalAttempts),
			// 	logger.Uint64("timeouts", stats.TotalTimeouts),
			// 	logger.Uint64("success", stats.TotalSuccess),
			// 	logger.Uint64("failures", stats.TotalFailures),
			// )

			// if sm, ok := s.socket.(*ipsec.SocketManager); ok {
			// 	sockStats := sm.Stats()
			// 	s.Logger.Debug("Socket 统计",
			// 		logger.Uint64("spii", s.SPIi),
			// 		logger.Uint64("spir", s.SPIr),
			// 		logger.Uint64("ikeRecv", sockStats.ReceivedIKE),
			// 		logger.Uint64("espRecv", sockStats.ReceivedESP),
			// 		logger.Uint64("ikeDrop", sockStats.DroppedIKE),
			// 		logger.Uint64("espDrop", sockStats.DroppedESP),
			// 	)
			// }
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
					s.Logger.Debug("NAT keepalive 发送失败", logger.Err(err))
				}
			}
		}
	}()
}

// startIKESARekeyTimer 启动 IKE SA 生命周期管理
// 定期触发 IKE SA Rekey，在 ePDG 8 分钟超时前刷新整个 IKE SA
// 连续失败 rekeyMaxFail 次后触发隧道重建
func (s *Session) startIKESARekeyTimer(interval time.Duration) {
	const rekeyMaxFail = 2

	// 初始化 rekey 重置 channel
	s.rekeyResetCh = make(chan struct{}, 1)

	go func() {
		timer := time.NewTimer(interval)
		defer timer.Stop()

		failCount := 0

		for {
			select {
			case <-s.ctx.Done():
				return
			case <-s.rekeyResetCh:
				// IKE SA Rekey 成功，重置计时器
				failCount = 0
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(interval)
				s.Logger.Debug("IKE SA Rekey 成功，Timer 已重置",
					logger.Duration("interval", interval))
			case <-timer.C:
				s.Logger.Info("IKE SA 生命周期到期，发起主动 IKE SA Rekey",
					logger.Duration("interval", interval))
				if err := s.RekeyIKESA(); err != nil {
					failCount++
					s.Logger.Warn("IKE SA Rekey 失败",
						logger.Err(err),
						logger.Int("连续失败", failCount))

					if failCount >= rekeyMaxFail {
						s.Logger.Error("IKE SA Rekey 连续失败达上限，触发隧道重建",
							logger.Int("maxFail", rekeyMaxFail))
						if s.OnSessionDown != nil {
							go s.OnSessionDown()
						} else if s.cancel != nil {
							s.cancel()
						}
						return
					}
					timer.Reset(60 * time.Second)
				} else {
					failCount = 0
					timer.Reset(interval)
				}
			}
		}
	}()
}

// startChildSARekeyTimer 启动 Child SA 生命周期管理
// 定期触发 CHILD_SA Rekey，在 ePDG ~8 分钟 ESP SA 过期前刷新密钥
// 连续失败 rekeyMaxFail 次后触发隧道重建
// 参考 strongSwan rekey_child_sa_job + jitter 机制
func (s *Session) startChildSARekeyTimer(interval time.Duration) {
	const rekeyMaxFail = 2

	// 初始化 child rekey 重置 channel
	s.childRekeyResetCh = make(chan struct{}, 1)

	go func() {
		// 首次启动添加 jitter，避免多设备同时 Rekey
		jitter := time.Duration(rand.Int63n(int64(childRekeyJitter))) * time.Second
		timer := time.NewTimer(interval - jitter)
		defer timer.Stop()

		failCount := 0

		for {
			select {
			case <-s.ctx.Done():
				return
			case <-s.childRekeyResetCh:
				// Child SA Rekey 成功（主动/被动），重置计时器
				failCount = 0
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				jitter = time.Duration(rand.Int63n(int64(childRekeyJitter))) * time.Second
				timer.Reset(interval - jitter)
				s.Logger.Debug("Child SA Rekey Timer 已重置",
					logger.Duration("interval", interval-jitter))
			case <-timer.C:
				s.Logger.Info("Child SA 生命周期到期，发起主动 Child SA Rekey",
					logger.Duration("interval", interval))
				if err := s.RekeyChildSA(); err != nil {
					failCount++
					s.Logger.Warn("Child SA Rekey 失败",
						logger.Err(err),
						logger.Int("连续失败", failCount))

					if failCount >= rekeyMaxFail {
						s.Logger.Error("Child SA Rekey 连续失败达上限，触发隧道重建",
							logger.Int("maxFail", rekeyMaxFail))
						if s.OnSessionDown != nil {
							go s.OnSessionDown()
						} else if s.cancel != nil {
							s.cancel()
						}
						return
					}
					timer.Reset(60 * time.Second) // 失败后 1 分钟重试
				} else {
					failCount = 0
					jitter = time.Duration(rand.Int63n(int64(childRekeyJitter))) * time.Second
					timer.Reset(interval - jitter)
				}
			}
		}
	}()
}

// startXFRMExpireMonitor 监听内核 XFRM_MSG_EXPIRE 事件
// Soft Expire: SA 接近过期，触发主动 Child SA Rekey
// Hard Expire: SA 已过期，触发隧道重建
func (s *Session) startXFRMExpireMonitor() {
	if s.xfrmMgr == nil {
		return
	}

	ch := make(chan netlink.XfrmMsg)
	done := make(chan struct{})
	errCh := make(chan error, 1)

	if err := netlink.XfrmMonitor(ch, done, errCh, nl.XFRM_MSG_EXPIRE); err != nil {
		s.Logger.Warn("启动 XFRM Expire 监听失败", logger.Err(err))
		return
	}

	s.Logger.Info("XFRM SA Expire 监听已启动")

	go func() {
		defer close(done)

		for {
			select {
			case <-s.ctx.Done():
				return
			case err := <-errCh:
				s.Logger.Warn("XFRM 监听错误", logger.Err(err))
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				expire, ok := msg.(*netlink.XfrmMsgExpire)
				if !ok || expire.XfrmState == nil {
					continue
				}

				// 过滤：只处理本 session 的 SA
				spi := uint32(expire.XfrmState.Spi)
				isOurSA := false
				if s.ChildSAOut != nil && s.ChildSAOut.SPI == spi {
					isOurSA = true
				}
				if s.ChildSAIn != nil && s.ChildSAIn.SPI == spi {
					isOurSA = true
				}
				if !isOurSA {
					continue
				}

				if expire.Hard {
					s.Logger.Warn("XFRM SA Hard Expire，触发隧道重建",
						logger.Uint32("spi", spi))
					if s.OnSessionDown != nil {
						go s.OnSessionDown()
					} else if s.cancel != nil {
						s.cancel()
					}
				} else {
					// Soft Expire 触发主动 Child SA Rekey
					s.Logger.Info("XFRM SA Soft Expire，触发主动 Child SA Rekey",
						logger.Uint32("spi", spi))
					go func() {
						if err := s.RekeyChildSA(); err != nil {
							s.Logger.Warn("Soft Expire 触发 Rekey 失败", logger.Err(err))
						}
					}()
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
				s.Logger.Warn("设置 TUN MTU 失败，将继续", logger.String("iface", s.tun.DeviceName()), logger.Int("mtu", mtu), logger.Err(err))
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
				s.Logger.Warn("设置 TUN MTU 失败，将继续", logger.String("iface", s.tun.DeviceName()), logger.Int("mtu", mtu), logger.Err(err))
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

// setupXFRMDataPlane 配置 XFRM 模式的数据平面
// 创建 XFRM Interface、安装 SA 和 SP，配置 ESP-in-UDP 封装
func (s *Session) setupXFRMDataPlane() error {
	s.Logger.Debug("设置 XFRMI 数据平面")

	xfrmMgr := driver.NewXFRMManager()
	s.xfrmMgr = xfrmMgr

	// 1. 在 socket 上设置 UDP_ENCAP_ESPINUDP
	if sm, ok := s.socket.(*ipsec.SocketManager); ok {
		if err := sm.SetUDPEncap(); err != nil {
			return fmt.Errorf("设置 UDP_ENCAP 失败: %v", err)
		}
	}

	// 2. 获取网络参数
	var localIP, remoteIP net.IP
	var localPort, remotePort int
	if sm, ok := s.socket.(*ipsec.SocketManager); ok {
		localIP = sm.LocalIP()
		remoteIP = sm.RemoteIP()
		localPort = int(sm.LocalPort())
		remotePort = sm.RemotePort()

		// 如果绑定的是 0.0.0.0，需要探测实际出口 IP 用于 SA Src
		if localIP.IsUnspecified() {
			s.Logger.Debug("LocalIP 未指定 (0.0.0.0)，尝试探测实际出口 IP", logger.String("remote", s.cfg.EpDGAddr))
			// 使用 UDP 探测路由出口 IP
			addr := net.JoinHostPort(s.cfg.EpDGAddr, fmt.Sprintf("%d", remotePort))
			conn, err := net.Dial("udp", addr)
			if err == nil {
				localIP = conn.LocalAddr().(*net.UDPAddr).IP
				conn.Close()
				s.Logger.Debug("探测到实际出口 IP", logger.String("ip", localIP.String()))
			} else {
				s.Logger.Warn("探测实际出口 IP 失败，将使用 0.0.0.0 (可能导致 XFRM 封装失败)", logger.Err(err))
			}
		}
	} else {
		return errors.New("XFRMI 模式需要 SocketManager")
	}

	// 3. 创建 XFRM 接口
	xfrmIfName := s.cfg.XFRMIfName
	if xfrmIfName == "" {
		xfrmIfName = "ipsec0"
	}
	xfrmIfID := s.cfg.XFRMIfID
	// Linux 内核要求 xfrm if_id > 0，使用出站 SPI 作为默认值（保证非零且唯一）
	if xfrmIfID == 0 {
		xfrmIfID = s.ChildSAOut.SPI
		if xfrmIfID == 0 {
			xfrmIfID = 42 // 最终兜底
		}
	}

	// 查找 Underlying Interface (物理接口)
	// XFRMI 接口最好绑定到底层物理接口，以便内核正确关联流量，避免 TX Error
	var underlyingIdx int
	if localIP != nil {
		if ifaces, err := net.Interfaces(); err == nil {
			for _, iface := range ifaces {
				if addrs, err := iface.Addrs(); err == nil {
					for _, addr := range addrs {
						// addr is *net.IPNet
						if ipnet, ok := addr.(*net.IPNet); ok {
							if ipnet.IP.Equal(localIP) {
								underlyingIdx = iface.Index
								s.Logger.Debug("绑定底层物理接口", logger.String("iface", iface.Name), logger.Int("idx", iface.Index))
								break
							}
						}
					}
				}
				if underlyingIdx > 0 {
					break
				}
			}
		}
	}

	// [Fix Zombie Interfaces] 强制清理同名接口，防止残留导致的状态错乱
	_ = xfrmMgr.DelXFRMInterface(xfrmIfName)

	if err := xfrmMgr.AddXFRMInterface(xfrmIfName, xfrmIfID, underlyingIdx); err != nil {
		return fmt.Errorf("创建 XFRM 接口失败: %v", err)
	}
	s.netUndos = append(s.netUndos, func() error {
		return xfrmMgr.DelXFRMInterface(xfrmIfName)
	})

	// 4. 构建 SA 配置参数
	// 确保 Socket 启用 UDP 封装 (XFRM 需要)
	if sm, ok := s.socket.(*ipsec.SocketManager); ok {
		if err := sm.SetUDPEncap(); err != nil {
			s.Logger.Warn("设置 Socket UDP Encap 失败", logger.Err(err))
		}
	}

	isAEAD := driver.IsAEADAlgorithm(s.childEncrID)

	// 出站 SA (本端 → ePDG)
	outSACfg := driver.XFRMSAConfig{
		Src:           localIP,
		Dst:           remoteIP,
		SPI:           s.ChildSAOut.SPI,
		Proto:         netlink.XFRM_PROTO_ESP,
		Mode:          netlink.XFRM_MODE_TUNNEL,
		IsAEAD:        isAEAD,
		EncapType:     netlink.XFRM_ENCAP_ESPINUDP,
		EncapSrcPort:  localPort,
		EncapDstPort:  remotePort,
		Ifid:          int(xfrmIfID),
		TimeLimitSoft: 0, // 不设 expire（由 IKE SA Rekey 管理生命周期）
		TimeLimitHard: 0,
		ReplayWindow:  s.cfg.ReplayWindow,
		SADir:         netlink.XFRM_SA_DIR_OUT,
		ESN:           s.childESN,
	}

	// 入站 SA (ePDG → 本端)
	inSACfg := driver.XFRMSAConfig{
		Src:           remoteIP,
		Dst:           localIP,
		SPI:           s.ChildSAIn.SPI,
		Proto:         netlink.XFRM_PROTO_ESP,
		Mode:          netlink.XFRM_MODE_TUNNEL,
		IsAEAD:        isAEAD,
		EncapType:     netlink.XFRM_ENCAP_ESPINUDP,
		EncapSrcPort:  remotePort,
		EncapDstPort:  localPort,
		Ifid:          int(xfrmIfID),
		TimeLimitSoft: 0,
		TimeLimitHard: 0,
		ReplayWindow:  s.cfg.ReplayWindow,
		SADir:         netlink.XFRM_SA_DIR_IN,
		ESN:           s.childESN,
	}

	// 配置算法参数
	if isAEAD {
		aeadInfo, err := driver.IKEv2AlgToXFRMAead(s.childEncrID, s.childEncrKeyLenBits)
		if err != nil {
			return fmt.Errorf("映射 AEAD 算法失败: %v", err)
		}
		outSACfg.AeadAlgoName = aeadInfo.Name
		outSACfg.AeadKey = s.ChildSAOut.EncryptionKey // 包含 encKey + salt
		outSACfg.AeadICVLen = aeadInfo.ICVBits

		inSACfg.AeadAlgoName = aeadInfo.Name
		inSACfg.AeadKey = s.ChildSAIn.EncryptionKey
		inSACfg.AeadICVLen = aeadInfo.ICVBits
	} else {
		cryptInfo, err := driver.IKEv2AlgToXFRMCrypt(s.childEncrID, s.childEncrKeyLenBits)
		if err != nil {
			return fmt.Errorf("映射加密算法失败: %v", err)
		}
		authInfo, err := driver.IKEv2AlgToXFRMAuth(s.childIntegID)
		if err != nil {
			return fmt.Errorf("映射完整性算法失败: %v", err)
		}
		outSACfg.CryptAlgoName = cryptInfo.Name
		outSACfg.CryptKey = s.ChildSAOut.EncryptionKey
		outSACfg.AuthAlgoName = authInfo.Name
		outSACfg.AuthKey = s.ChildSAOut.IntegrityKey
		outSACfg.AuthTruncLen = authInfo.TruncateBits

		inSACfg.CryptAlgoName = cryptInfo.Name
		inSACfg.CryptKey = s.ChildSAIn.EncryptionKey
		inSACfg.AuthAlgoName = authInfo.Name
		inSACfg.AuthKey = s.ChildSAIn.IntegrityKey
		inSACfg.AuthTruncLen = authInfo.TruncateBits
	}

	// 5. 安装 SA
	if err := xfrmMgr.AddSA(outSACfg); err != nil {
		return err
	}
	s.netUndos = append(s.netUndos, func() error {
		return xfrmMgr.DelSA(outSACfg.SPI, outSACfg.Src, outSACfg.Dst, outSACfg.Proto)
	})

	if err := xfrmMgr.AddSA(inSACfg); err != nil {
		return err
	}
	s.netUndos = append(s.netUndos, func() error {
		return xfrmMgr.DelSA(inSACfg.SPI, inSACfg.Src, inSACfg.Dst, inSACfg.Proto)
	})

	s.Logger.Debug("XFRM SA 已安装",
		logger.Uint32("outSPI", outSACfg.SPI),
		logger.Uint32("inSPI", inSACfg.SPI),
		logger.String("local", localIP.String()),
		logger.String("remote", remoteIP.String()),
	)

	// 缓存网络参数供 rekey 时复用
	s.xfrmLocalIP = localIP
	s.xfrmRemoteIP = remoteIP
	s.xfrmLocalPort = localPort
	s.xfrmRemotePort = remotePort
	s.xfrmIfID = int(xfrmIfID)

	// 6. 安装 SP (出站和入站)
	allIPv4 := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	allIPv6 := &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}

	// 出站 SP (IPv4)
	outSP4 := driver.XFRMSPConfig{
		Src:       allIPv4,
		Dst:       allIPv4,
		Dir:       netlink.XFRM_DIR_OUT,
		TmplSrc:   localIP,
		TmplDst:   remoteIP,
		TmplProto: netlink.XFRM_PROTO_ESP,
		TmplMode:  netlink.XFRM_MODE_TUNNEL,
		TmplSPI:   int(outSACfg.SPI), // 显式绑定 SPI
		Ifid:      int(xfrmIfID),
	}
	if err := xfrmMgr.AddSP(outSP4); err != nil {
		return err
	}
	s.netUndos = append(s.netUndos, func() error { return xfrmMgr.DelSP(outSP4) })

	// 入站 SP (IPv4)
	inSP4 := driver.XFRMSPConfig{
		Src:       allIPv4,
		Dst:       allIPv4,
		Dir:       netlink.XFRM_DIR_IN,
		TmplSrc:   remoteIP,
		TmplDst:   localIP,
		TmplProto: netlink.XFRM_PROTO_ESP,
		TmplMode:  netlink.XFRM_MODE_TUNNEL,
		TmplSPI:   int(inSACfg.SPI), // 显式验证 SPI
		Ifid:      int(xfrmIfID),
	}
	if err := xfrmMgr.AddSP(inSP4); err != nil {
		return err
	}
	s.netUndos = append(s.netUndos, func() error { return xfrmMgr.DelSP(inSP4) })

	// 转发 SP (IPv4)
	fwdSP4 := driver.XFRMSPConfig{
		Src:       allIPv4,
		Dst:       allIPv4,
		Dir:       netlink.XFRM_DIR_FWD,
		TmplSrc:   remoteIP,
		TmplDst:   localIP,
		TmplProto: netlink.XFRM_PROTO_ESP,
		TmplMode:  netlink.XFRM_MODE_TUNNEL,
		Ifid:      int(xfrmIfID),
	}
	if err := xfrmMgr.AddSP(fwdSP4); err != nil {
		s.Logger.Warn("添加 FWD SP 失败 (非致命)", logger.Err(err))
	} else {
		s.netUndos = append(s.netUndos, func() error { return xfrmMgr.DelSP(fwdSP4) })
	}

	// IPv6 SP (强制安装，覆盖所有 IPv6 流量，即使没有 CP 配置也要允许链路本地流量)
	outSP6 := driver.XFRMSPConfig{
		Src: allIPv6, Dst: allIPv6, Dir: netlink.XFRM_DIR_OUT,
		TmplSrc: localIP, TmplDst: remoteIP,
		TmplProto: netlink.XFRM_PROTO_ESP, TmplMode: netlink.XFRM_MODE_TUNNEL,
		TmplSPI: int(outSACfg.SPI), // 显式绑定 SPI
		Ifid:    int(xfrmIfID),
	}
	// Panic removed
	if err := xfrmMgr.AddSP(outSP6); err != nil {
		s.Logger.Warn("添加 IPv6 出站 SP 失败 (非致命)", logger.Err(err))
	} else {
		s.netUndos = append(s.netUndos, func() error { return xfrmMgr.DelSP(outSP6) })
	}

	inSP6 := driver.XFRMSPConfig{
		Src: allIPv6, Dst: allIPv6, Dir: netlink.XFRM_DIR_IN,
		TmplSrc: remoteIP, TmplDst: localIP,
		TmplProto: netlink.XFRM_PROTO_ESP, TmplMode: netlink.XFRM_MODE_TUNNEL,
		TmplSPI: int(inSACfg.SPI), // 显式验证 SPI
		Ifid:    int(xfrmIfID),
	}
	if err := xfrmMgr.AddSP(inSP6); err != nil {
		s.Logger.Warn("添加 IPv6 入站 SP 失败 (非致命)", logger.Err(err))
	} else {
		s.netUndos = append(s.netUndos, func() error { return xfrmMgr.DelSP(inSP6) })
	}

	s.Logger.Debug("XFRM SP 已安装")

	// 缓存所有 SP 配置（MOBIKE 地址更新时使用）
	s.xfrmPolicies = []driver.XFRMSPConfig{outSP4, inSP4, fwdSP4, outSP6, inSP6}

	// 7. 在 XFRM 接口上配置 IP 地址和路由
	// 复用 applyNetworkConfigOnTUN (它只依赖接口名)
	if err := s.net.SetLinkUp(xfrmIfName); err != nil {
		return fmt.Errorf("启动 XFRM 接口失败: %v", err)
	}
	mtu := s.cfg.TUNMTU
	if mtu == 0 {
		mtu = 1280 // XFRMI 可以用更大的 MTU (内核处理开销更小)
	}
	if mtu > 0 && s.cpConfig != nil && len(s.cpConfig.IPv6Addresses) > 0 && mtu < 1280 {
		mtu = 1280
	}
	if mtu > 0 {
		if err := s.net.SetMTU(xfrmIfName, mtu); err != nil {
			s.Logger.Warn("设置 XFRM 接口 MTU 失败", logger.Err(err))
		}
	}

	if err := s.applyNetworkConfigOnTUN(xfrmIfName); err != nil {
		s.cleanupNetworkConfig()
		return fmt.Errorf("在 XFRM 接口上配置网络失败: %v", err)
	}

	s.Logger.Info("XFRMI 数据平面已就绪",
		logger.String("iface", xfrmIfName),
		logger.Uint32("ifID", xfrmIfID),
		logger.Int("mtu", mtu))

	return nil
}

// rekeyXFRMSA 在 CHILD_SA Rekey 后更新内核 XFRM SA 和 SP
// 流程：删除旧 SA → 安装新 SA → 更新 SP 模板 SPI（通过 Update 语义）
func (s *Session) rekeyXFRMSA(oldOutSPI, oldInSPI uint32, newSAOut, newSAIn *ipsec.SecurityAssociation, encrID uint16, encrKeyLenBits int) error {
	xfrmMgr := s.xfrmMgr
	if xfrmMgr == nil {
		return nil
	}

	localIP := s.xfrmLocalIP
	remoteIP := s.xfrmRemoteIP
	localPort := s.xfrmLocalPort
	remotePort := s.xfrmRemotePort
	ifid := s.xfrmIfID

	// 1. 删除旧 SA
	_ = xfrmMgr.DelSA(oldOutSPI, localIP, remoteIP, netlink.XFRM_PROTO_ESP)
	_ = xfrmMgr.DelSA(oldInSPI, remoteIP, localIP, netlink.XFRM_PROTO_ESP)

	// 2. 构建新 SA 配置
	isAEAD := driver.IsAEADAlgorithm(encrID)

	outSACfg := driver.XFRMSAConfig{
		Src:           localIP,
		Dst:           remoteIP,
		SPI:           newSAOut.SPI,
		Proto:         netlink.XFRM_PROTO_ESP,
		Mode:          netlink.XFRM_MODE_TUNNEL,
		IsAEAD:        isAEAD,
		EncapType:     netlink.XFRM_ENCAP_ESPINUDP,
		EncapSrcPort:  localPort,
		EncapDstPort:  remotePort,
		Ifid:          ifid,
		TimeLimitSoft: 0,
		TimeLimitHard: 0,
		ReplayWindow:  s.cfg.ReplayWindow,
		SADir:         netlink.XFRM_SA_DIR_OUT,
		ESN:           s.childESN,
	}

	inSACfg := driver.XFRMSAConfig{
		Src:           remoteIP,
		Dst:           localIP,
		SPI:           newSAIn.SPI,
		Proto:         netlink.XFRM_PROTO_ESP,
		Mode:          netlink.XFRM_MODE_TUNNEL,
		IsAEAD:        isAEAD,
		EncapType:     netlink.XFRM_ENCAP_ESPINUDP,
		EncapSrcPort:  remotePort,
		EncapDstPort:  localPort,
		Ifid:          ifid,
		TimeLimitSoft: 0,
		TimeLimitHard: 0,
		ReplayWindow:  s.cfg.ReplayWindow,
		SADir:         netlink.XFRM_SA_DIR_IN,
		ESN:           s.childESN,
	}

	// 配置算法
	if isAEAD {
		aeadInfo, err := driver.IKEv2AlgToXFRMAead(encrID, encrKeyLenBits)
		if err != nil {
			return fmt.Errorf("Rekey 映射 AEAD 算法失败: %v", err)
		}
		outSACfg.AeadAlgoName = aeadInfo.Name
		outSACfg.AeadKey = newSAOut.EncryptionKey
		outSACfg.AeadICVLen = aeadInfo.ICVBits

		inSACfg.AeadAlgoName = aeadInfo.Name
		inSACfg.AeadKey = newSAIn.EncryptionKey
		inSACfg.AeadICVLen = aeadInfo.ICVBits
	} else {
		cryptInfo, err := driver.IKEv2AlgToXFRMCrypt(encrID, encrKeyLenBits)
		if err != nil {
			return fmt.Errorf("Rekey 映射加密算法失败: %v", err)
		}
		authInfo, err := driver.IKEv2AlgToXFRMAuth(s.childIntegID)
		if err != nil {
			return fmt.Errorf("Rekey 映射完整性算法失败: %v", err)
		}
		outSACfg.CryptAlgoName = cryptInfo.Name
		outSACfg.CryptKey = newSAOut.EncryptionKey
		outSACfg.AuthAlgoName = authInfo.Name
		outSACfg.AuthKey = newSAOut.IntegrityKey
		outSACfg.AuthTruncLen = authInfo.TruncateBits

		inSACfg.CryptAlgoName = cryptInfo.Name
		inSACfg.CryptKey = newSAIn.EncryptionKey
		inSACfg.AuthAlgoName = authInfo.Name
		inSACfg.AuthKey = newSAIn.IntegrityKey
		inSACfg.AuthTruncLen = authInfo.TruncateBits
	}

	// 3. 安装新 SA
	if err := xfrmMgr.AddSA(outSACfg); err != nil {
		return fmt.Errorf("Rekey 安装出站 SA 失败: %v", err)
	}
	if err := xfrmMgr.AddSA(inSACfg); err != nil {
		return fmt.Errorf("Rekey 安装入站 SA 失败: %v", err)
	}

	// 4. 更新 SP 模板中的 SPI（使用 Update 语义覆盖旧 SP）
	allIPv4 := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	allIPv6 := &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}

	// 出站 SP (IPv4 + IPv6)
	for _, src := range []*net.IPNet{allIPv4, allIPv6} {
		_ = xfrmMgr.AddSP(driver.XFRMSPConfig{
			Src: src, Dst: src, Dir: netlink.XFRM_DIR_OUT,
			TmplSrc: localIP, TmplDst: remoteIP,
			TmplProto: netlink.XFRM_PROTO_ESP, TmplMode: netlink.XFRM_MODE_TUNNEL,
			TmplSPI: int(newSAOut.SPI), Ifid: ifid,
		})
	}
	// 入站 SP (IPv4 + IPv6)
	for _, src := range []*net.IPNet{allIPv4, allIPv6} {
		_ = xfrmMgr.AddSP(driver.XFRMSPConfig{
			Src: src, Dst: src, Dir: netlink.XFRM_DIR_IN,
			TmplSrc: remoteIP, TmplDst: localIP,
			TmplProto: netlink.XFRM_PROTO_ESP, TmplMode: netlink.XFRM_MODE_TUNNEL,
			TmplSPI: int(newSAIn.SPI), Ifid: ifid,
		})
	}

	s.Logger.Debug("XFRM SA/SP 已更新 (Rekey)",
		logger.Uint32("newOutSPI", newSAOut.SPI),
		logger.Uint32("newInSPI", newSAIn.SPI))

	return nil
}

type netToolsDeleter interface {
	DelAddress(iface string, cidr string) error
	DelRoute(cidr string, gw string, iface string) error
	DelAddress6(iface string, cidr string) error
	DelRoute6(cidr string, gw string, iface string) error
}

func (s *Session) applyNetworkConfigOnTUN(iface string) error {
	s.Logger.Debug("Applying network config on TUN", logger.String("iface", iface), logger.Bool("has_driver", s.net != nil))

	if s.net == nil {
		return nil
	}
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

	// 检查是否支持策略路由
	// 如果支持，我们允许添加 0.0.0.0/0 默认路由（因为它会被隔离在独立的路由表中）
	// 如果不支持，我们需要跳过默认路由，防止覆盖宿主机的默认网关
	type policyRouter interface {
		AddRouteTable(cidr string, iface string, table int) error
		DelRouteTable(cidr string, iface string, table int) error
		AddRule(srcCIDR string, table int) error
		DelRule(srcCIDR string, table int) error
		AddInputRule(iface string, table int) error
		DelInputRule(iface string, table int) error
		CleanConflictRoutes(cidrs []string, keepIface string, family int)
		SetSysctl(key, value string) error
	}
	_, enablePolicyRouting := s.net.(policyRouter)

	for _, ts := range s.tsr {
		if ts.TSType != ikev2.TS_IPV4_ADDR_RANGE && ts.TSType != ikev2.TS_IPV6_ADDR_RANGE {
			continue
		}

		// IPv4 处理
		if ts.TSType == ikev2.TS_IPV4_ADDR_RANGE {
			// 如果不支持策略路由，且是全网段，则跳过 (保护宿主机)
			if !enablePolicyRouting && isFullIPv4Range(ts) {
				s.Logger.Debug("Skipping full range IPv4 TS to protect host default gateway", logger.String("start", net.IP(ts.StartAddr).String()))
				continue
			}

			// 如果是全网段，直接添加 0.0.0.0/0
			if isFullIPv4Range(ts) {
				s.Logger.Debug("PolicyRouting: Adding default IPv4 route (0.0.0.0/0)", logger.Int("table", 0)) // table ID not avail here, just info
				routes = append(routes, "0.0.0.0/0")
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

		// IPv6 处理
		if ts.TSType == ikev2.TS_IPV6_ADDR_RANGE {
			// 如果不支持策略路由，且是全网段，则跳过
			if !enablePolicyRouting && isFullIPv6Range(ts) {
				s.Logger.Warn("Skipping full range IPv6 TS to protect host default gateway")
				continue
			}

			// 如果是全网段，直接添加 ::/0
			if isFullIPv6Range(ts) {
				s.Logger.Debug("PolicyRouting: Adding default IPv6 route (::/0)")
				routes6 = append(routes6, "::/0")
				continue
			}

			// 简单处理：如果是单个 IP
			if len(ts.StartAddr) == 16 && len(ts.EndAddr) == 16 {
				start := net.IP(ts.StartAddr)
				end := net.IP(ts.EndAddr)
				if start.Equal(end) {
					routes6 = append(routes6, fmt.Sprintf("%s/128", start.String()))
				} else {
					// TODO: 完整的 IPv6 范围转 CIDR 比较复杂，暂时只支持全网段或单IP
					// 如果不是全网段，我们暂不添加详细路由，或者等待后续完善
					s.Logger.Warn("Skipping complex IPv6 range", logger.String("start", start.String()), logger.String("end", end.String()))
				}
			}
		}
	}

	// 尝试使用策略路由（独立路由表），避免多设备共享 P-CSCF 等场景下路由冲突
	if pr, ok := s.net.(policyRouter); ok {
		enablePolicyRouting = true
		s.Logger.Info("Policy routing supported by driver", logger.String("iface", iface))
		// 使用 TUN 接口的 link index 作为路由表 ID（避免与系统表冲突，加偏移 1000）
		link, err := s.net.(*driver.NetTools).GetLink(iface)
		if err == nil {
			tableID := link.Attrs().Index + 1000

			// 1. 添加基于入站接口 (iif) 的策略路由规则：iif <iface> lookup <tableID>
			// 这解决了 RPF (反向路径过滤) 问题：确保入站包能匹配到正确的路由表
			if err := pr.AddInputRule(iface, tableID); err != nil {
				return err
			}
			tbl := tableID
			s.netUndos = append(s.netUndos, func() error { return pr.DelInputRule(iface, tbl) })

			// 2. 添加基于源地址的策略路由规则：from <设备IP> lookup <tableID>
			var srcCIDRs []string
			if s.cpConfig != nil {
				for _, ip := range s.cpConfig.IPv4Addresses {
					if v4 := ip.To4(); v4 != nil {
						srcCIDRs = append(srcCIDRs, fmt.Sprintf("%s/32", v4.String()))
					}
				}
				for _, ip := range s.cpConfig.IPv6Addresses {
					if v6 := ip.To16(); v6 != nil {
						srcCIDRs = append(srcCIDRs, fmt.Sprintf("%s/128", v6.String()))
					}
				}
			}

			// 先添加 ip rule
			for _, src := range srcCIDRs {
				if err := pr.AddRule(src, tableID); err != nil {
					return err
				}
				srcCopy := src
				tbl := tableID
				s.netUndos = append(s.netUndos, func() error { return pr.DelRule(srcCopy, tbl) })
			}

			// 再添加路由到独立路由表
			for _, cidr := range routes {
				if err := pr.AddRouteTable(cidr, iface, tableID); err != nil {
					return err
				}
				c := cidr
				tbl := tableID
				s.netUndos = append(s.netUndos, func() error { return pr.DelRouteTable(c, iface, tbl) })
			}
			for _, cidr := range routes6 {
				// Revert: StrongSwan uses direct routes. Let's try direct routes again with ARP enabled.
				if err := pr.AddRouteTable(cidr, iface, tableID); err != nil {
					return err
				}
				c := cidr
				tbl := tableID
				s.netUndos = append(s.netUndos, func() error { return pr.DelRouteTable(c, iface, tbl) })
			}

			// [清理 main 表冲突路由]
			// 其他设备或旧 session 可能在 main 表中留下到 P-CSCF 的路由 (dev ens2)，
			// 这些路由会抢占策略路由，导致 Go dial tcp 走物理接口而非 XFRM 隧道
			pr.CleanConflictRoutes(routes6, iface, netlink.FAMILY_V6)
			pr.CleanConflictRoutes(routes, iface, netlink.FAMILY_V4)

			// XFRM 接口初始化：确保 IPv6 可用
			go func() {
				time.Sleep(500 * time.Millisecond)
				// 确保接口 UP
				if nt, ok := s.net.(*driver.NetTools); ok {
					_ = nt.SetLinkUp(iface)
					// 添加 Link-Local 地址（XFRM 接口无 ARP 可能不会自动生成）
					_ = nt.AddAddress6(iface, "fe80::1/64")
				}
				// 确保 IPv6 启用且禁用 DAD（XFRM 接口无需邻居发现）
				_ = pr.SetSysctl(fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", iface), "0")
				_ = pr.SetSysctl(fmt.Sprintf("net.ipv6.conf.%s.accept_dad", iface), "0")
			}()

			return nil
		}
	}

	// 回退：使用默认路由表（单设备场景或不支持策略路由时）
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
	s.Logger.Info("ESP 数据平面循环启动", logger.String("tun", s.tun.DeviceName()))

	// TUN -> ESP
	go func() {
		s.Logger.Info("TUN->ESP goroutine 启动")
		buf := make([]byte, 2000)
		var tunReadCount, espSendCount, saDropCount uint64
		for {
			n, err := s.tun.Read(buf)
			if err != nil {
				s.Logger.Info("TUN 读取结束", logger.Err(err))
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
					s.Logger.Warn("ESP 出站 SA 为空，丢弃数据包",
						logger.Uint64("dropCount", saDropCount),
						logger.String("dstIP", dstIP),
						logger.Int("proto", int(proto)),
						logger.Int("len", n))
				}
				continue
			}

			espPacket, err := ipsec.Encapsulate(packet, saOut)
			if err != nil {
				s.Logger.Warn("ESP 封装错误", logger.Err(err), logger.String("dstIP", dstIP))
				continue
			}

			if err := s.socket.SendESP(espPacket); err != nil {
				s.Logger.Warn("ESP 发送失败", logger.Err(err), logger.String("dstIP", dstIP))
				continue
			}

			espSendCount++
			if espSendCount <= 10 || espSendCount%100 == 0 {
				s.Logger.Debug("ESP 已发送",
					logger.Uint64("count", espSendCount),
					logger.String("dstIP", dstIP),
					logger.Int("proto", int(proto)),
					logger.Int("plainLen", n),
					logger.Int("espLen", len(espPacket)),
					logger.Uint32("spi", saOut.SPI))
			}
		}
		s.Logger.Info("TUN->ESP 循环退出", logger.Uint64("tunRead", tunReadCount), logger.Uint64("espSend", espSendCount), logger.Uint64("saDrop", saDropCount))
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
				s.Logger.Warn("ESP 入站 SA 为空，丢弃数据包", logger.Uint32("spi", spi), logger.Int("len", len(espData)))
				continue
			}

			packet, err := ipsec.Decapsulate(espData, sa)
			if err != nil {
				s.Logger.Warn("ESP 解封装错误", logger.Err(err), logger.Uint32("spi", spi), logger.Int("len", len(espData)))
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

	// IKE Fragmentation (RFC 7383): 如果消息过大且对端支持分片，则分片发送
	if s.shouldFragment(payloads) {
		packets, err := s.fragmentMessage(payloads, exchangeType)
		if err != nil {
			return nil, fmt.Errorf("IKE 分片失败: %v", err)
		}
		if len(packets) > 0 {
			// 分片模式: 发送所有分片，等待最后一个分片的响应
			// 所有分片共享同一个 Message ID
			msgID := s.SequenceNumber - 1
			for _, pkt := range packets {
				if err := s.socket.SendIKE(pkt); err != nil {
					return nil, fmt.Errorf("发送 IKE 分片失败: %v", err)
				}
			}
			// 等待响应
			return s.receiveIKEResponseWithTimeout(exchangeType, msgID, 10*time.Second)
		}
	}

	// 正常（非分片）发送
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
