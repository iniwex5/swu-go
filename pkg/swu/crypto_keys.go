package swu

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"

	"github.com/iniwex5/swu-go/pkg/crypto"
	"github.com/iniwex5/swu-go/pkg/ikev2"
)

// GenerateIKESAKeys 根据 RFC 7296 2.13 和 2.14 生成密钥
func (s *Session) GenerateIKESAKeys(peerNonce []byte) error {
	// 1. 计算 SKEYSEED = prf(Ni | Nr, g^ir)
	if s.DH.SharedKey == nil {
		return errors.New("DH 共享密钥未计算")
	}

	seed := append(s.ni, peerNonce...)

	prf := s.PRFAlg
	mac := hmac.New(prf.Hash, seed)
	mac.Write(s.DH.SharedKey)
	skeyseed := mac.Sum(nil)

	// 2. 计算密钥
	totalLen := 0
	prfKeyLen := prf.KeyLen()

	encKeyLen := 0
	if s.EncAlg == nil {
		return errors.New("IKE 加密算法未设置")
	}
	if s.ikeIsAEAD {
		encKeyLen = s.EncAlg.KeySize() + 4
	} else {
		encKeyLen = s.EncAlg.KeySize()
	}

	integKeyLen := 0
	if !s.ikeIsAEAD {
		if s.IntegAlg == nil {
			return errors.New("IKE 完整性算法未设置")
		}
		integKeyLen = s.IntegAlg.KeySize()
	}

	totalLen += prfKeyLen * 3   // SK_d, SK_pi, SK_pr
	totalLen += integKeyLen * 2 // SK_ai, SK_ar
	totalLen += encKeyLen * 2   // SK_ei, SK_er

	input := append(s.ni, peerNonce...)
	spiBytes := make([]byte, 16)
	binary.BigEndian.PutUint64(spiBytes[0:8], s.SPIi)
	binary.BigEndian.PutUint64(spiBytes[8:16], s.SPIr)
	input = append(input, spiBytes...)

	keyMat, err := crypto.PrfPlus(prf, skeyseed, input, totalLen)
	if err != nil {
		return err
	}

	s.Keys = &ikev2.IKESAKeys{}
	cursor := 0

	s.Keys.SK_d = keyMat[cursor : cursor+prfKeyLen]
	cursor += prfKeyLen

	if integKeyLen > 0 {
		s.Keys.SK_ai = keyMat[cursor : cursor+integKeyLen]
		cursor += integKeyLen
		s.Keys.SK_ar = keyMat[cursor : cursor+integKeyLen]
		cursor += integKeyLen
	}

	s.Keys.SK_ei = keyMat[cursor : cursor+encKeyLen]
	cursor += encKeyLen
	s.Keys.SK_er = keyMat[cursor : cursor+encKeyLen]
	cursor += encKeyLen

	s.Keys.SK_pi = keyMat[cursor : cursor+prfKeyLen]
	cursor += prfKeyLen
	s.Keys.SK_pr = keyMat[cursor : cursor+prfKeyLen]

	return nil
}
