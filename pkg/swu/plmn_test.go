package swu

import "testing"

func TestBuildAKAIdentityForEAPTypeHonorsEPCNAIModeOnAKAPrime(t *testing.T) {
	cfg := &Config{
		MCC:             "228",
		MNC:             "02",
		AKAIdentityMode: "epc_nai",
	}
	got := buildAKAIdentityForEAPType("228021331813774", cfg, 50)
	wantPrefix := "0228021331813774@nai.epc.mnc002.mcc228.3gppnetwork.org"
	if got != wantPrefix {
		t.Fatalf("unexpected aka' identity for epc_nai mode: got=%q want=%q", got, wantPrefix)
	}
}

func TestBuildAKAIdentityForEAPTypeUsesSixPrefixWhenNotPinned(t *testing.T) {
	cfg := &Config{
		MCC:             "228",
		MNC:             "02",
		AKAIdentityMode: "wlan_nai",
	}
	got := buildAKAIdentityForEAPType("228021331813774", cfg, 50)
	wantPrefix := "6228021331813774@nai.epc.mnc002.mcc228.3gppnetwork.org"
	if got != wantPrefix {
		t.Fatalf("unexpected aka' identity for non-epc mode: got=%q want=%q", got, wantPrefix)
	}
}
