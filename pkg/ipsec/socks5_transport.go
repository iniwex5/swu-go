// Socks5Transport 通过 Socks5 UDP Associate 代理 IKE/ESP 流量的 Transport 实现
// TCP 控制通道负责维持 UDP Associate 会话存活，UDP Relay 负责数据转发
package ipsec

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iniwex5/swu-go/pkg/logger"
)

// Socks5Config 配置 Socks5 代理连接参数
type Socks5Config struct {
	ProxyAddr  string // Socks5 服务器地址 (host:port)
	Username   string // 可选鉴权用户名
	Password   string // 可选鉴权密码
	RemoteAddr string // 目标 ePDG 地址 (host:port)
	DNSServer  string // DNS 服务器（用于解析 ePDG 域名）
	DeviceID   string // 设备标识
}

// Socks5Transport 实现 swu.Transport 接口，通过 Socks5 代理转发 UDP 流量
type Socks5Transport struct {
	cfg Socks5Config

	// TCP 控制通道
	tcpConn net.Conn

	// UDP 数据通道
	udpConn   *net.UDPConn // 本地 UDP Socket（与 Relay 通信）
	relayAddr *net.UDPAddr // Socks5 服务器分配的 Relay UDP 地址

	// 目标 ePDG 地址
	remoteIP   net.IP
	remotePort int
	remoteMu   sync.RWMutex

	// 本地地址
	localIP   net.IP
	localPort uint16

	// 分发通道
	ikeChan   chan []byte
	espChan   chan []byte
	netEvents chan NetEvent

	// 生命周期管理
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// 统计
	receivedIKE uint64
	receivedESP uint64
	droppedIKE  uint64
	droppedESP  uint64
}

// NewSocks5Transport 创建 Socks5 代理传输层
// 完成 TCP 握手 → UDP ASSOCIATE → 本地 UDP 初始化
func NewSocks5Transport(cfg Socks5Config) (*Socks5Transport, error) {
	// 解析目标 ePDG 地址
	rAddr, err := net.ResolveUDPAddr("udp", cfg.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: 解析目标地址 %s 失败: %w", cfg.RemoteAddr, err)
	}

	// 第一步：建立 TCP 控制连接
	proxyHost, proxyPort, err := parseSocks5Addr(cfg.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: 解析代理地址 %s 失败: %w", cfg.ProxyAddr, err)
	}
	tcpAddr := net.JoinHostPort(proxyHost, fmt.Sprintf("%d", proxyPort))
	tcpConn, err := net.DialTimeout("tcp", tcpAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("socks5: TCP 连接 %s 失败: %w", tcpAddr, err)
	}

	// 第二步：Socks5 握手鉴权
	var cred *Socks5Credential
	if cfg.Username != "" {
		cred = &Socks5Credential{Username: cfg.Username, Password: cfg.Password}
	}
	if err := socks5Handshake(tcpConn, cred); err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5: 握手失败: %w", err)
	}

	// 第三步：UDP ASSOCIATE
	relayAddr, err := socks5UDPAssociate(tcpConn, &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5: UDP ASSOCIATE 失败: %w", err)
	}

	// 如果 Relay 地址为 0.0.0.0，替换为代理服务器的实际 IP
	if relayAddr.IP.IsUnspecified() {
		if tcpRemote, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
			relayAddr.IP = tcpRemote.IP
		}
	}

	// 第四步：创建本地 UDP Socket 用于与 Relay 通信
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5: 创建 UDP Socket 失败: %w", err)
	}

	// 获取本地绑定地址
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)

	ctx, cancel := context.WithCancel(context.Background())

	t := &Socks5Transport{
		cfg:        cfg,
		tcpConn:    tcpConn,
		udpConn:    udpConn,
		relayAddr:  relayAddr,
		remoteIP:   rAddr.IP,
		remotePort: rAddr.Port,
		localIP:    localAddr.IP,
		localPort:  uint16(localAddr.Port),
		ikeChan:    make(chan []byte, 128),
		espChan:    make(chan []byte, 512),
		netEvents:  make(chan NetEvent, 16),
		ctx:        ctx,
		cancel:     cancel,
	}

	logger.Info("socks5: 代理传输层初始化成功",
		logger.String("proxy", cfg.ProxyAddr),
		logger.String("relay", relayAddr.String()),
		logger.String("remote", rAddr.String()),
		logger.String("local_udp", localAddr.String()),
		logger.String("device", cfg.DeviceID))

	return t, nil
}

// Start 启动接收循环和 TCP 保活监控
func (t *Socks5Transport) Start() {
	t.wg.Add(2)
	go t.readLoop()
	go t.tcpKeepalive()
}

// Stop 停止所有 goroutine 并关闭连接
func (t *Socks5Transport) Stop() {
	t.cancel()
	_ = t.udpConn.Close()
	_ = t.tcpConn.Close()
	t.wg.Wait()
}

// SendIKE 通过 Socks5 UDP Relay 发送 IKE 包
func (t *Socks5Transport) SendIKE(data []byte) error {
	return t.sendUDP(data)
}

// SendESP 通过 Socks5 UDP Relay 发送 ESP 包
func (t *Socks5Transport) SendESP(data []byte) error {
	return t.sendUDP(data)
}

// IKEPackets 返回 IKE 数据接收通道
func (t *Socks5Transport) IKEPackets() <-chan []byte {
	return t.ikeChan
}

// ESPPackets 返回 ESP 数据接收通道
func (t *Socks5Transport) ESPPackets() <-chan []byte {
	return t.espChan
}

// NetEventsChan 返回网络事件通道
func (t *Socks5Transport) NetEventsChan() <-chan NetEvent {
	return t.netEvents
}

// LocalIP 返回本地 UDP Socket 的 IP 地址
func (t *Socks5Transport) LocalIP() net.IP {
	return t.localIP
}

// RemoteIP 返回目标 ePDG 的 IP 地址
func (t *Socks5Transport) RemoteIP() net.IP {
	t.remoteMu.RLock()
	defer t.remoteMu.RUnlock()
	return t.remoteIP
}

// LocalPort 返回本地 UDP Socket 的端口
func (t *Socks5Transport) LocalPort() uint16 {
	return t.localPort
}

// RemotePort 返回目标 ePDG 的端口
func (t *Socks5Transport) RemotePort() int {
	t.remoteMu.RLock()
	defer t.remoteMu.RUnlock()
	return t.remotePort
}

// SetRemotePort 更新目标端口（NAT-T 切换 500 → 4500）
func (t *Socks5Transport) SetRemotePort(port int) {
	t.remoteMu.Lock()
	defer t.remoteMu.Unlock()
	t.remotePort = port
	logger.Debug("socks5: 远端端口已更新",
		logger.Int("port", port),
		logger.String("device", t.cfg.DeviceID))
}

// LocalAddrString 返回本地地址的字符串表示
func (t *Socks5Transport) LocalAddrString() string {
	return fmt.Sprintf("%s:%d (via socks5 %s)", t.localIP, t.localPort, t.cfg.ProxyAddr)
}

// RemoteAddrString 返回远端地址的字符串表示
func (t *Socks5Transport) RemoteAddrString() string {
	t.remoteMu.RLock()
	defer t.remoteMu.RUnlock()
	return fmt.Sprintf("%s:%d", t.remoteIP, t.remotePort)
}

// sendUDP 构造 Socks5 UDP Datagram 并通过 Relay 转发
func (t *Socks5Transport) sendUDP(data []byte) error {
	t.remoteMu.RLock()
	dst := &net.UDPAddr{IP: t.remoteIP, Port: t.remotePort}
	t.remoteMu.RUnlock()

	// 封装 Socks5 UDP Header + 原始数据
	datagram := EncodeSocks5UDPDatagram(dst, data)

	_, err := t.udpConn.WriteToUDP(datagram, t.relayAddr)
	if err != nil {
		return fmt.Errorf("socks5: 发送 UDP 失败: %w", err)
	}
	return nil
}

// readLoop 从 Relay 读取 UDP 数据，剥离 Socks5 Header 后分发到 IKE/ESP 通道
func (t *Socks5Transport) readLoop() {
	defer t.wg.Done()

	buf := make([]byte, 65535)
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		_ = t.udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := t.udpConn.ReadFromUDP(buf)
		if err != nil {
			if t.ctx.Err() != nil {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			logger.Warn("socks5: UDP 读取失败",
				logger.String("err", err.Error()),
				logger.String("device", t.cfg.DeviceID))
			continue
		}

		// 解码 Socks5 UDP Datagram
		datagram, err := DecodeSocks5UDPDatagram(buf[:n])
		if err != nil {
			logger.Debug("socks5: 解码 UDP Datagram 失败",
				logger.String("err", err.Error()))
			continue
		}

		// 分片的数据报暂不支持，直接丢弃
		if datagram.Frag != 0 {
			continue
		}

		payload := datagram.Data
		if len(payload) == 0 {
			continue
		}

		// 根据包头判断是 IKE 还是 ESP
		// IKE 包的第 17-20 字节（MessageID 之前）包含固定的 NextPayload + Version + Exchange + Flags
		// ESP 包则以 SPI(4字节) + SequenceNumber(4字节) 开头
		// 简单判断：如果长度 >= 28 且 byte[17] & 0x20 == 0x20 (IKE Version 2.0)，按 IKE 处理
		if isIKEPacket(payload) {
			atomic.AddUint64(&t.receivedIKE, 1)
			select {
			case t.ikeChan <- copyBytes(payload):
			default:
				atomic.AddUint64(&t.droppedIKE, 1)
			}
		} else {
			atomic.AddUint64(&t.receivedESP, 1)
			select {
			case t.espChan <- copyBytes(payload):
			default:
				atomic.AddUint64(&t.droppedESP, 1)
			}
		}
	}
}

// isIKEPacket 判断负载是否为 IKE 包
// IKE 包结构：SPIi(8) + SPIr(8) + NextPayload(1) + Version(1) + ExchangeType(1) + Flags(1) + ...
// Version 字段固定为 0x20 (IKEv2 major=2, minor=0)
func isIKEPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	// IKE Header 的第 17 字节 (从0开始) 是 Version，IKEv2 = 0x20
	version := data[17]
	if version == 0x20 {
		return true
	}
	// NAT-T 模式下 ESP-in-UDP 包前面有 4 字节 Non-ESP Marker (全零)
	// IKE-over-4500 包也有 4 字节 Non-ESP Marker
	if len(data) >= 4 && binary.BigEndian.Uint32(data[:4]) == 0 {
		// 非 ESP Marker，剥离后检查是否为 IKE
		if len(data) >= 24 && data[21] == 0x20 {
			return true
		}
	}
	return false
}

// tcpKeepalive 监控 TCP 控制通道存活
// RFC 1928: TCP 连接断开意味着 UDP Association 失效
func (t *Socks5Transport) tcpKeepalive() {
	defer t.wg.Done()

	buf := make([]byte, 1)
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}

		// 尝试读取 TCP，正常情况下不会收到数据
		// 如果连接断开，Read 会立即返回错误
		_ = t.tcpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, err := t.tcpConn.Read(buf)
		if err != nil {
			if t.ctx.Err() != nil {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 超时是正常的，说明连接还活着
				continue
			}
			// TCP 连接断开
			logger.Warn("socks5: TCP 控制通道断开，UDP Relay 将失效",
				logger.String("err", err.Error()),
				logger.String("device", t.cfg.DeviceID))

			// 通知上层
			select {
			case t.netEvents <- NetEvent{Type: EventNetworkDown}:
			default:
			}
			return
		}
	}
}

// copyBytes 创建字节切片的独立副本
func copyBytes(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	return out
}
