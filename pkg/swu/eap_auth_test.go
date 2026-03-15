package swu

import (
	"crypto/sha1"
	"fmt"
	"testing"
)

func TestEAPAKACheckcode(t *testing.T) {
	s := &Session{}

	// 模拟 RFC 序列
	p1 := []byte{0x01, 0x01, 0x00, 0x0a, 0x17, 0x05} // Identity Request
	p2 := []byte{0x02, 0x01, 0x00, 0x10, 0x17, 0x05} // Identity Response
	p3 := []byte{0x01, 0x02, 0x00, 0x20, 0x17, 0x01} // Challenge Request

	s.appendEAPTranscript(p1)
	s.appendEAPTranscript(p2)
	s.appendEAPTranscript(p3)

	if len(s.eapTranscript) != 3 {
		t.Fatalf("expected 3 packets in transcript, got %d", len(s.eapTranscript))
	}

	checkcode := s.calcAKACheckcode("sha1")

	// 手动计算预期
	h := sha1.New()
	h.Write(p1)
	h.Write(p2)
	h.Write(p3)
	expected := h.Sum(nil)

	if fmt.Sprintf("%x", checkcode) != fmt.Sprintf("%x", expected) {
		t.Errorf("Checkcode mismatch!\nGot: %x\nExp: %x", checkcode, expected)
	} else {
		t.Logf("Checkcode verified: %x", checkcode)
	}
}
