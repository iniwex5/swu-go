package swu

type Transport interface {
	Start()
	Stop()
	SendIKE([]byte) error
	SendESP([]byte) error
	IKEPackets() <-chan []byte
	ESPPackets() <-chan []byte
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

