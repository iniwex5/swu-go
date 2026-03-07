package swu

import (
	"net"

	"github.com/iniwex5/swu-go/pkg/ikev2"
)

type SessionSnapshot struct {
	Established bool
	TUNName     string
	LastError   string
	IKEProfile  string
	IKEEncr     string
	IKEInteg    string
	IKEPRF      string
	IKEDH       string

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
	out.LastError = s.terminalError()
	out.IKEProfile = snapshotIKEProfile(s.ikeEncrID, s.ikeIntegID, s.ikePRFID)
	out.IKEEncr = ikev2.EncrToString(s.ikeEncrID)
	out.IKEInteg = ikev2.IntegToString(s.ikeIntegID)
	out.IKEPRF = ikev2.PRFToString(s.ikePRFID)
	if s.DH != nil {
		out.IKEDH = ikev2.DHToString(uint16(s.DH.Group))
	}
	// 启用了数据平面驱动时
	if s.cfg.EnableDriver {
		if s.cfg.DataplaneMode == "xfrmi" {
			if out.Established && s.xfrmMgr == nil {
				out.Established = false
			}
			if s.xfrmMgr != nil {
				out.TUNName = s.cfg.TUNName
			}
		} else {
			if out.Established && s.tun == nil {
				out.Established = false
			}
			if s.tun != nil {
				out.TUNName = s.tun.DeviceName()
			}
		}
	} else {
		// 无驱动模式下，只看 SA
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

func snapshotIKEProfile(encrID, integID, prfID uint16) string {
	switch {
	case integID == uint16(ikev2.AUTH_HMAC_SHA2_256_128) && prfID == uint16(ikev2.PRF_HMAC_SHA2_256):
		return "sha2_modern"
	case integID == uint16(ikev2.AUTH_HMAC_SHA1_96) && prfID == uint16(ikev2.PRF_HMAC_SHA1):
		return "sha1_legacy"
	case integID == uint16(ikev2.AUTH_AES_XCBC_96) && prfID == uint16(ikev2.PRF_AES128_XCBC):
		return "xcbc_legacy"
	default:
		return "mixed"
	}
}
