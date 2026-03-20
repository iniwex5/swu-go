package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestAKAPrimeKeySeed(t *testing.T) {
	got := akaPrimeKeySeed("6imsi@nai.epc.mnc001.mcc001.3gppnetwork.org")
	want := []byte("EAP-AKA'6imsi@nai.epc.mnc001.mcc001.3gppnetwork.org")
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected seed: got=%q want=%q", string(got), string(want))
	}
}

func TestPrf256PlusRFCOrder(t *testing.T) {
	key := []byte("test-key")
	seed := []byte("EAP-AKA'identity@example")

	got := prf256Plus(key, seed, 64)

	h1 := hmac.New(sha256.New, key)
	h1.Write(seed)
	h1.Write([]byte{0x01})
	t1 := h1.Sum(nil)

	h2 := hmac.New(sha256.New, key)
	h2.Write(t1)
	h2.Write(seed)
	h2.Write([]byte{0x02})
	t2 := h2.Sum(nil)

	want := append(append([]byte{}, t1...), t2...)
	if !bytes.Equal(got, want[:64]) {
		t.Fatalf("prf256Plus mismatch:\n got=%x\nwant=%x", got, want[:64])
	}
}

func TestPrf256PlusSeedAffectsOutput(t *testing.T) {
	key := []byte("same-key")
	outA := prf256Plus(key, []byte("seed-a"), 32)
	outB := prf256Plus(key, []byte("seed-b"), 32)
	if bytes.Equal(outA, outB) {
		t.Fatalf("expected different output for different seeds, got same: %x", outA)
	}
}
