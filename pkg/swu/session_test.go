package swu

import (
	"bytes"
	"testing"

	"github.com/iniwex5/swu-go/pkg/crypto"
	"github.com/iniwex5/swu-go/pkg/ikev2"
)

func TestGenerateIKESAKeys(t *testing.T) {
	// Mock Session
	s := &Session{
		SPIi: 0x1122334455667788,
		SPIr: 0x8877665544332211,
		ni:   make([]byte, 32),
		nr:   make([]byte, 32),
	}

	// Mock DH Shared Key (32 bytes)
	sharedKey := make([]byte, 256) // 2048 bits
	// fill pattern
	for i := range sharedKey {
		sharedKey[i] = 0xAA
	}

	s.DH = &crypto.DiffieHellman{SharedKey: sharedKey}
	s.PRFAlg, _ = crypto.GetPRF(uint16(ikev2.PRF_HMAC_SHA2_256)) // Match constants
	s.EncAlg, _ = crypto.GetEncrypter(uint16(ikev2.ENCR_AES_GCM_16))
	s.ikeIsAEAD = true
	s.IntegAlg, _ = crypto.GetIntegrityAlgorithm(0)
	// Wait, constants.go defines PRF_HMAC_SHA2_256 as AlgorithmType = 5.
	// But crypto.GetPRF expects uint16(5). Correct.

	// Run
	err := s.GenerateIKESAKeys(s.nr)
	if err != nil {
		t.Fatalf("GenerateIKESAKeys failed: %v", err)
	}

	if len(s.Keys.SK_d) != 32 {
		t.Errorf("SK_d length mismatch: got %d, want 32", len(s.Keys.SK_d))
	}
	if len(s.Keys.SK_ei) != 20 { // 16 Key + 4 Salt
		t.Errorf("SK_ei length mismatch: got %d, want 20", len(s.Keys.SK_ei))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	s := &Session{
		SPIi: 0x1122334455667788,
		SPIr: 0x8877665544332211,
	}

	// Setup Keys for GCM
	// Key 16, Salt 4
	key := make([]byte, 20)
	copy(key, []byte("1234567890123456salt"))

	s.Keys = &ikev2.IKESAKeys{
		SK_ei: key,
		SK_er: key,
	}

	s.EncAlg, _ = crypto.GetEncrypter(19) // AES_GCM_12 (Wait, I used 19 in state_init?)
	// Let's check state_init which algorithm ID I used.
	// state_init uses ikev2.ENCR_AES_GCM_16 (20).
	// crypto.GetEncrypter supports 18, 19, 20.
	s.EncAlg, _ = crypto.GetEncrypter(20)
	s.ikeIsAEAD = true
	s.IntegAlg, _ = crypto.GetIntegrityAlgorithm(0)

	// Create Payload
	idPayload := &ikev2.EncryptedPayloadID{
		IDType: ikev2.ID_IPV4_ADDR,
		IDData: []byte{192, 168, 1, 1},
	}

	// Encrypt
	data, err := s.encryptAndWrap([]ikev2.Payload{idPayload}, ikev2.IKE_AUTH, false)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Log packet size
	t.Logf("Encrypted Packet Size: %d", len(data))

	// Decrypt
	msgID, payloads, err := s.decryptAndParse(data)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if msgID != 1 {
		t.Errorf("Message ID mismatch: got %d, want 1", msgID)
	}

	if len(payloads) != 1 {
		t.Fatalf("Payload count mismatch: got %d", len(payloads))
	}

	p, ok := payloads[0].(*ikev2.EncryptedPayloadID)
	if !ok {
		t.Errorf("Payload type mismatch")
	}

	if !bytes.Equal(p.IDData, []byte{192, 168, 1, 1}) {
		t.Errorf("ID Data content mismatch")
	}
}
