package swu

import (
	"net"
	"testing"
)

func TestIPv4RangeToCIDRs(t *testing.T) {
	cidrs, err := ipv4RangeToCIDRs(net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 255))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cidrs) != 1 || cidrs[0] != "10.0.0.0/24" {
		t.Fatalf("unexpected cidrs: %v", cidrs)
	}

	cidrs, err = ipv4RangeToCIDRs(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 1))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cidrs) != 1 || cidrs[0] != "10.0.0.1/32" {
		t.Fatalf("unexpected cidrs: %v", cidrs)
	}

	cidrs, err = ipv4RangeToCIDRs(net.IPv4(0, 0, 0, 0), net.IPv4(255, 255, 255, 255))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cidrs) != 1 || cidrs[0] != "0.0.0.0/0" {
		t.Fatalf("unexpected cidrs: %v", cidrs)
	}
}

