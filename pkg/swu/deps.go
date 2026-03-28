package swu

import (
	"net"

	"github.com/iniwex5/swu-go/pkg/ipsec"
)

type Transport interface {
	Start()
	Stop()
	SendIKE([]byte) error
	SendESP([]byte) error
	IKEPackets() <-chan []byte
	ESPPackets() <-chan []byte
	NetEventsChan() <-chan ipsec.NetEvent

	// 地址信息方法：消除对 *ipsec.SocketManager 的类型断言依赖
	LocalIP() net.IP
	RemoteIP() net.IP
	LocalPort() uint16
	RemotePort() int
	SetRemotePort(port int)
	LocalAddrString() string
	RemoteAddrString() string
}

type TUN interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	DeviceName() string
}

type NetTools interface {
	SetLinkUp(iface string) error
	AddAddress(iface string, cidr string) error
	AddRoute(cidr string, gw string, iface string) error
	SetMTU(iface string, mtu int) error
	AddAddress6(iface string, cidr string) error
	AddRoute6(cidr string, gw string, iface string) error
}
