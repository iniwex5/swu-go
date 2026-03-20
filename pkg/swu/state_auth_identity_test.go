package swu

import (
	"strings"
	"testing"

	"github.com/iniwex5/swu-go/pkg/eap"
	"github.com/iniwex5/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

type identityTestSIM struct {
	imsi string
}

func (m identityTestSIM) GetIMSI() (string, error) {
	return m.imsi, nil
}

func (m identityTestSIM) CalculateAKA(rand []byte, autn []byte) (res, ck, ik, auts []byte, err error) {
	return nil, nil, nil, nil, nil
}

func (m identityTestSIM) Close() error {
	return nil
}

func TestHandleEAPTypeIdentityUsesAKAPrimePrefixWhenPreferred(t *testing.T) {
	s := NewSession(&Config{
		SIM:               identityTestSIM{imsi: "228021331813774"},
		AKAPrimePreferred: true,
	}, zap.NewNop())

	req := (&eap.EAPPacket{
		Code:       eap.CodeRequest,
		Identifier: 0x01,
		Type:       eap.TypeIdentity,
	}).Encode()

	payloads, err := s.handleEAP(req)
	if err != nil {
		t.Fatalf("handleEAP returned unexpected error: %v", err)
	}
	if len(payloads) != 1 {
		t.Fatalf("expected exactly 1 payload, got %d", len(payloads))
	}

	eapPayload, ok := payloads[0].(*ikev2.EncryptedPayloadEAP)
	if !ok {
		t.Fatalf("expected EncryptedPayloadEAP, got %T", payloads[0])
	}
	respPkt, err := eap.Parse(eapPayload.EAPMessage)
	if err != nil {
		t.Fatalf("failed to parse EAP response: %v", err)
	}
	if respPkt.Type != eap.TypeIdentity {
		t.Fatalf("expected TypeIdentity response, got type=%d", respPkt.Type)
	}

	got := string(respPkt.Data)
	if !strings.HasPrefix(got, "6") {
		t.Fatalf("expected AKA' preferred identity prefix '6', got %q", got)
	}
}

func TestHandleEAPTypeIdentityUsesAKAPrefixByDefault(t *testing.T) {
	s := NewSession(&Config{
		SIM:               identityTestSIM{imsi: "228021331813774"},
		AKAPrimePreferred: false,
	}, zap.NewNop())

	req := (&eap.EAPPacket{
		Code:       eap.CodeRequest,
		Identifier: 0x01,
		Type:       eap.TypeIdentity,
	}).Encode()

	payloads, err := s.handleEAP(req)
	if err != nil {
		t.Fatalf("handleEAP returned unexpected error: %v", err)
	}
	if len(payloads) != 1 {
		t.Fatalf("expected exactly 1 payload, got %d", len(payloads))
	}

	eapPayload, ok := payloads[0].(*ikev2.EncryptedPayloadEAP)
	if !ok {
		t.Fatalf("expected EncryptedPayloadEAP, got %T", payloads[0])
	}
	respPkt, err := eap.Parse(eapPayload.EAPMessage)
	if err != nil {
		t.Fatalf("failed to parse EAP response: %v", err)
	}
	if respPkt.Type != eap.TypeIdentity {
		t.Fatalf("expected TypeIdentity response, got type=%d", respPkt.Type)
	}

	got := string(respPkt.Data)
	if !strings.HasPrefix(got, "0") {
		t.Fatalf("expected default AKA identity prefix '0', got %q", got)
	}
}
