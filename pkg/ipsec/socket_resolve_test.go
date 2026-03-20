package ipsec

import "testing"

func TestResolveUDPAddrAllUsesSystemResolverWhenDNSEmpty(t *testing.T) {
	addr, all, err := resolveUDPAddrAll("localhost:500", "")
	if err != nil {
		t.Fatalf("resolveUDPAddrAll(localhost) error: %v", err)
	}
	if addr == nil || addr.IP == nil {
		t.Fatalf("expected resolved addr with IP, got %+v", addr)
	}
	if len(all) == 0 {
		t.Fatalf("expected at least one candidate IP from system resolver")
	}
	found := false
	for _, ip := range all {
		if ip != nil && ip.Equal(addr.IP) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("selected IP %v not present in candidates %v", addr.IP, all)
	}
}

func TestResolveUDPAddrAllLiteralIPKeepsSingleCandidate(t *testing.T) {
	addr, all, err := resolveUDPAddrAll("127.0.0.1:500", "")
	if err != nil {
		t.Fatalf("resolveUDPAddrAll(literal ip) error: %v", err)
	}
	if addr == nil || addr.IP == nil {
		t.Fatalf("expected resolved addr with IP, got %+v", addr)
	}
	if len(all) != 1 {
		t.Fatalf("expected exactly one candidate for literal IP, got %d (%v)", len(all), all)
	}
	if !all[0].Equal(addr.IP) {
		t.Fatalf("candidate %v != selected %v", all[0], addr.IP)
	}
}
