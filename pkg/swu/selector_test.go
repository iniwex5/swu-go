package swu

import (
	"net"
	"testing"

	"github.com/iniwex5/swu-go/pkg/ikev2"
	"github.com/iniwex5/swu-go/pkg/ipsec"
)

func TestSelectOutgoingSAMatchTSR(t *testing.T) {
	s := &Session{}

	a := &ipsec.SecurityAssociation{SPI: 1}
	b := &ipsec.SecurityAssociation{SPI: 2}
	s.ChildSAOut = a

	tsrA := []*ikev2.TrafficSelector{
		ikev2.NewTrafficSelectorIPV4(net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 255), 0, 65535),
	}
	tsrB := []*ikev2.TrafficSelector{
		ikev2.NewTrafficSelectorIPV4(net.IPv4(192, 168, 0, 0), net.IPv4(192, 168, 0, 255), 0, 65535),
	}
	s.childOutPolicies = []childOutPolicy{
		{saOut: a, tsr: tsrA},
		{saOut: b, tsr: tsrB},
	}

	pkt := buildIPv4UDP(net.IPv4(1, 1, 1, 1), net.IPv4(192, 168, 0, 5), 10000, 5060)
	got := s.selectOutgoingSA(pkt)
	if got == nil || got.SPI != 2 {
		t.Fatalf("expected sa SPI=2, got=%v", got)
	}
}

func buildIPv4UDP(src, dst net.IP, sport, dport uint16) []byte {
	ip := make([]byte, 20+8)
	ip[0] = 0x45
	ip[9] = 17
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	ip[20] = byte(sport >> 8)
	ip[21] = byte(sport)
	ip[22] = byte(dport >> 8)
	ip[23] = byte(dport)
	return ip
}

