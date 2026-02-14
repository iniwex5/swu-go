package swu

import "net"

type SessionSnapshot struct {
	Established bool
	TUNName     string

	IPv4       net.IP
	IPv6       net.IP
	IPv6Prefix int

	DNSv4 []net.IP
	DNSv6 []net.IP

	PCSCFv4 []net.IP
	PCSCFv6 []net.IP
}

func (s *Session) Snapshot() SessionSnapshot {
	out := SessionSnapshot{}
	out.Established = s.ChildSAIn != nil && s.ChildSAOut != nil
	// 启用了数据平面驱动时，TUN 接口也必须就绪才算 Established
	if out.Established && s.cfg.EnableDriver && s.tun == nil {
		out.Established = false
	}
	if s.tun != nil {
		out.TUNName = s.tun.DeviceName()
	}
	if s.cpConfig != nil {
		if len(s.cpConfig.IPv4Addresses) > 0 {
			out.IPv4 = append(net.IP(nil), s.cpConfig.IPv4Addresses[0]...)
		}
		if len(s.cpConfig.IPv6Addresses) > 0 {
			out.IPv6 = append(net.IP(nil), s.cpConfig.IPv6Addresses[0]...)
		}
		if s.cpConfig.IPv6Prefix != 0 {
			out.IPv6Prefix = int(s.cpConfig.IPv6Prefix)
		}
		for _, ip := range s.cpConfig.IPv4DNS {
			out.DNSv4 = append(out.DNSv4, append(net.IP(nil), ip...))
		}
		for _, ip := range s.cpConfig.IPv6DNS {
			out.DNSv6 = append(out.DNSv6, append(net.IP(nil), ip...))
		}
		for _, ip := range s.cpConfig.IPv4PCSCF {
			out.PCSCFv4 = append(out.PCSCFv4, append(net.IP(nil), ip...))
		}
		for _, ip := range s.cpConfig.IPv6PCSCF {
			out.PCSCFv6 = append(out.PCSCFv6, append(net.IP(nil), ip...))
		}
	}
	if out.IPv6Prefix == 0 && out.IPv6 != nil {
		out.IPv6Prefix = 64
	}
	return out
}
