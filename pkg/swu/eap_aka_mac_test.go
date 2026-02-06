package swu

import (
	"crypto/hmac"
	"crypto/sha1"
	"testing"

	"github.com/iniwex5/swu-go/pkg/crypto"
	"github.com/iniwex5/swu-go/pkg/eap"
	"github.com/iniwex5/swu-go/pkg/ikev2"
	"github.com/iniwex5/swu-go/pkg/sim"
)

type testSIM struct {
	imsi string
	res  []byte
	ck   []byte
	ik   []byte
}

func (t *testSIM) GetIMSI() (string, error) { return t.imsi, nil }
func (t *testSIM) CalculateAKA(rand []byte, autn []byte) (res, ck, ik, auts []byte, err error) {
	return t.res, t.ck, t.ik, nil, nil
}
func (t *testSIM) Close() error { return nil }

func TestEAPAKAMACVerification(t *testing.T) {
	imsi := "001011234567890"
	mcc := "001"
	mnc := "01"

	simProv := &testSIM{
		imsi: imsi,
		res:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
		ck:   []byte("1234567890abcdef"),
		ik:   []byte("fedcba0987654321"),
	}
	_ = simProv

	cfg := &Config{
		SIM:                     simProv,
		MCC:                     mcc,
		MNC:                     mnc,
		DisableEAPMACValidation: false,
	}

	s := &Session{cfg: cfg}

	randVal := make([]byte, 16)
	autnVal := make([]byte, 16)
	for i := 0; i < 16; i++ {
		randVal[i] = byte(i)
		autnVal[i] = byte(16 - i)
	}

	atRand := (&eap.Attribute{Type: eap.AT_RAND, Value: append([]byte{0, 0}, randVal...)}).Encode()
	atAutn := (&eap.Attribute{Type: eap.AT_AUTN, Value: append([]byte{0, 0}, autnVal...)}).Encode()
	atMac := (&eap.Attribute{Type: eap.AT_MAC, Value: make([]byte, 18)}).Encode()

	attrs := append(append(atRand, atAutn...), atMac...)

	reqPkt := &eap.EAPPacket{
		Code:       eap.CodeRequest,
		Identifier: 7,
		Type:       eap.TypeAKA,
		Subtype:    eap.SubtypeChallenge,
		Data:       attrs,
	}
	eapBytes := reqPkt.Encode()

	identity := []byte(buildNAI(imsi, cfg))
	h := sha1.New()
	h.Write(identity)
	h.Write(simProv.ik)
	h.Write(simProv.ck)
	mk := h.Sum(nil)
	keyMat := crypto.NewFIPS1862PRFSHA1(mk).Bytes(nil, 16+16+64)
	kAut := keyMat[16:32]

	offset, ok := findEAPAttrOffset(reqPkt.Data, eap.AT_MAC)
	if !ok {
		t.Fatalf("cannot locate AT_MAC offset")
	}
	macPos := 8 + offset + 4
	if macPos+16 > len(eapBytes) {
		t.Fatalf("macPos out of range")
	}

	tmp := make([]byte, len(eapBytes))
	copy(tmp, eapBytes)
	copy(tmp[macPos:macPos+16], make([]byte, 16))

	mac := hmac.New(sha1.New, kAut)
	mac.Write(tmp)
	fullMac := mac.Sum(nil)
	copy(eapBytes[macPos:macPos+16], fullMac[:16])

	payloads, err := s.handleEAP(eapBytes)
	if err != nil {
		t.Fatalf("handleEAP failed: %v", err)
	}
	if len(payloads) != 1 {
		t.Fatalf("payload count mismatch: %d", len(payloads))
	}
	if _, ok := payloads[0].(*ikev2.EncryptedPayloadEAP); !ok {
		t.Fatalf("payload type mismatch: %T", payloads[0])
	}
}

var _ sim.SIMProvider = (*testSIM)(nil)
