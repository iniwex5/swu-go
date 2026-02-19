package swu

import (
	"github.com/iniwex5/swu-go/pkg/sim"
)

type Config struct {
	EpDGAddr  string
	EpDGPort  uint16 // 默认 500
	APN       string
	LocalAddr string // 传出接口 IP (通常自动检测)
	DNSServer string // 可选: 用于解析 ePDG 域名的 DNS 服务器 (host:port)

	SIM          sim.SIMProvider
	EnableDriver bool // 是否创建 TUN 和路由 (需要 root)

	// 数据平面模式: "tun" (默认，用户空间 ESP) 或 "xfrmi" (内核 XFRM offload)
	DataplaneMode string
	// XFRMI 模式专用配置
	XFRMIfName string // XFRM 接口名 (默认 "ipsec0")
	XFRMIfID   uint32 // XFRM interface ID (默认自动分配)

	// 可选的特定配置
	MCC       string
	MNC       string
	LocalPort uint16 // 本地 UDP 端口 (默认 500)
	// IKE SA 重认证间隔（秒），0 表示禁用
	// 默认 0 (不主动重认证，仅 Rekey)
	ReauthInterval int

	TUNName string // TUN 设备名 (默认自动分配)
	TUNMTU  int    // TUN MTU，0 表示使用默认值（当前默认 1200）

	// XFRM SA 抗重放窗口大小（0 = 使用默认值 32）
	// 高延迟/乱序网络建议设为 128 或 256
	ReplayWindow int

	// 启用 ESN（Extended Sequence Numbers, RFC 4303 §2.2.1）
	// 64 位序列号，防止高速网络下 32 位 SN 溢出
	// 默认 false（VoWiFi 场景通常不需要）
	EnableESN bool

	DisableEAPMACValidation bool

	EnableWiresharkKeyLog bool
	WiresharkKeyLogPath   string

	TransportFactory func(local string, remote string) (Transport, error)
	TUNFactory       func(name string) (TUN, error)
	NetTools         NetTools
}
