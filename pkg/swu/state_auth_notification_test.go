package swu

import (
	"testing"

	"github.com/iniwex5/swu-go/pkg/eap"
	"github.com/iniwex5/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func TestHandleEAPNotificationFailureCodeAckAndContinue(t *testing.T) {
	s := NewSession(&Config{}, zap.NewNop())

	atNotification := (&eap.Attribute{
		Type:  eap.AT_NOTIFICATION,
		Value: []byte{0x40, 0x00}, // 16384: General failure
	}).Encode()

	req := (&eap.EAPPacket{
		Code:       eap.CodeRequest,
		Identifier: 0x11,
		Type:       eap.TypeAKA,
		Subtype:    eap.SubtypeNotification,
		Data:       atNotification,
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
	if respPkt.Code != eap.CodeResponse {
		t.Fatalf("expected EAP Response, got code=%d", respPkt.Code)
	}
	if respPkt.Type != eap.TypeAKA {
		t.Fatalf("expected EAP Type AKA, got type=%d", respPkt.Type)
	}
	if respPkt.Subtype != eap.SubtypeNotification {
		t.Fatalf("expected EAP Subtype Notification, got subtype=%d", respPkt.Subtype)
	}
}
