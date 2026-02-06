package swu

import (
	"errors"
	"fmt"

	"github.com/iniwex5/swu-go/pkg/crypto"
	"github.com/iniwex5/swu-go/pkg/ikev2"
)

func (s *Session) decryptAndParse(data []byte) (uint32, []ikev2.Payload, error) {
	header, err := ikev2.DecodeHeader(data)
	if err != nil {
		return 0, nil, err
	}
	s.SPIr = header.SPIr

	if header.NextPayload != ikev2.SK {
		packet, err := ikev2.DecodePacket(data)
		return header.MessageID, packet.Payloads, err
	}

	// 处理 SK 载荷
	offset := ikev2.IKE_HEADER_LEN
	genHeader, err := ikev2.DecodePayloadHeader(data[offset : offset+4])
	if err != nil {
		return 0, nil, err
	}

	skBodyLen := int(genHeader.PayloadLength) - 4
	if offset+4+skBodyLen > len(data) {
		return 0, nil, errors.New("SK 载荷太短")
	}

	skContent := data[offset+4 : offset+4+skBodyLen]
	ivSize := s.EncAlg.IVSize()

	if len(skContent) < ivSize {
		return 0, nil, errors.New("SK 内容对于 IV 来说太短")
	}
	iv := skContent[:ivSize]
	aad := data[:ikev2.IKE_HEADER_LEN]
	key := s.Keys.SK_er

	ciphertext := skContent[ivSize:]
	if !s.ikeIsAEAD && s.IntegAlg != nil {
		icvSize := s.IntegAlg.OutputSize()
		if len(ciphertext) < icvSize {
			return 0, nil, errors.New("SK 内容对于 ICV 来说太短")
		}
		receivedICV := ciphertext[len(ciphertext)-icvSize:]
		ciphertext = ciphertext[:len(ciphertext)-icvSize]

		dataToVerify := data[:ikev2.IKE_HEADER_LEN+4+ivSize+len(ciphertext)]
		if !s.IntegAlg.Verify(s.Keys.SK_ar, dataToVerify, receivedICV) {
			return 0, nil, errors.New("IKE 完整性校验失败")
		}
	}

	plaintext, err := s.EncAlg.Decrypt(ciphertext, key, iv, aad)
	if err != nil {
		return 0, nil, fmt.Errorf("解密失败: %v", err)
	}

	if !s.ikeIsAEAD {
		if len(plaintext) < 1 {
			return 0, nil, errors.New("SK 明文太短")
		}
		padLen := int(plaintext[len(plaintext)-1])
		if len(plaintext) < 1+padLen {
			return 0, nil, errors.New("SK 填充长度无效")
		}
		plaintext = plaintext[:len(plaintext)-1-padLen]
	}

	payloads, err := s.parsePayloads(plaintext, genHeader.NextPayload)
	return header.MessageID, payloads, err
}

func (s *Session) parsePayloads(data []byte, firstType ikev2.PayloadType) ([]ikev2.Payload, error) {
	var payloads []ikev2.Payload
	offset := 0
	nextType := firstType

	for nextType != ikev2.NoNextPayload && offset < len(data) {
		if offset+4 > len(data) {
			break
		}
		genHeader, err := ikev2.DecodePayloadHeader(data[offset : offset+4])
		if err != nil {
			return nil, err
		}

		length := int(genHeader.PayloadLength)
		if offset+length > len(data) {
			return nil, errors.New("载荷太短")
		}

		body := data[offset+4 : offset+length]
		var p ikev2.Payload

		switch nextType {
		case ikev2.SA:
			p, err = ikev2.DecodePayloadSA(body)
		case ikev2.KE:
			p, err = ikev2.DecodePayloadKE(body)
		case ikev2.IDi, ikev2.IDr:
			p, err = ikev2.DecodePayloadID(body, nextType == ikev2.IDi)
		case ikev2.AUTH:
			p, err = ikev2.DecodePayloadAuth(body)
		case ikev2.EAP:
			p, err = ikev2.DecodePayloadEAP(body)
		case ikev2.CP:
			p, err = ikev2.DecodePayloadCP(body)
		case ikev2.D:
			p, err = ikev2.DecodePayloadDelete(body)
		case ikev2.TSI:
			p, err = ikev2.DecodePayloadTS(body, true)
		case ikev2.TSR:
			p, err = ikev2.DecodePayloadTS(body, false)
		case ikev2.N:
			p, err = ikev2.DecodePayloadNotify(body)
		default:
			p = &ikev2.RawPayload{PType: nextType, Data: body}
		}

		if err != nil {
			return nil, err
		}
		if p != nil {
			payloads = append(payloads, p)
		}

		nextType = genHeader.NextPayload
		offset += length
	}
	return payloads, nil
}

func (s *Session) encryptAndWrap(payloads []ikev2.Payload, exchangeType ikev2.ExchangeType, isResponse bool) ([]byte, error) {
	msgID := uint32(s.NextSequenceNumber())
	return s.encryptAndWrapWithMsgID(payloads, exchangeType, msgID, isResponse)
}

func (s *Session) encryptAndWrapWithMsgID(payloads []ikev2.Payload, exchangeType ikev2.ExchangeType, msgID uint32, isResponse bool) ([]byte, error) {
	innerData := []byte{}

	for i, pl := range payloads {
		nextType := ikev2.NoNextPayload
		if i < len(payloads)-1 {
			nextType = payloads[i+1].Type()
		}

		body, err := pl.Encode()
		if err != nil {
			return nil, err
		}

		header := &ikev2.PayloadHeader{
			NextPayload:   nextType,
			PayloadLength: uint16(4 + len(body)),
		}
		innerData = append(innerData, header.Encode()...)
		innerData = append(innerData, body...)
	}

	key := s.Keys.SK_ei
	iv, err := crypto.RandomBytes(s.EncAlg.IVSize())
	if err != nil {
		return nil, err
	}

	icvSize := 0
	if !s.ikeIsAEAD && s.IntegAlg != nil {
		icvSize = s.IntegAlg.OutputSize()
	}

	plainToEncrypt := innerData
	expectedCipherLen := len(plainToEncrypt)
	if s.ikeIsAEAD {
		expectedCipherLen += 16
	} else {
		blockSize := s.EncAlg.BlockSize()
		if blockSize <= 0 {
			return nil, errors.New("无效的块大小")
		}
		padLen := 0
		if rem := (len(plainToEncrypt) + 1) % blockSize; rem != 0 {
			padLen = blockSize - rem
		}
		plainToEncrypt = append(plainToEncrypt, make([]byte, padLen)...)
		plainToEncrypt = append(plainToEncrypt, byte(padLen))
		expectedCipherLen = len(plainToEncrypt)
	}

	nextPayload := ikev2.NoNextPayload
	if len(payloads) > 0 {
		nextPayload = payloads[0].Type()
	}

	hdr := &ikev2.IKEHeader{
		SPIi:         s.SPIi,
		SPIr:         s.SPIr,
		NextPayload:  ikev2.SK,
		Version:      0x20,
		ExchangeType: exchangeType,
		Flags:        ikev2.FlagInitiator,
		MessageID:    msgID,
		Length:       uint32(ikev2.IKE_HEADER_LEN + 4 + len(iv) + expectedCipherLen + icvSize),
	}
	if isResponse {
		hdr.Flags |= ikev2.FlagResponse
	}

	aad := hdr.Encode()
	ciphertext, err := s.EncAlg.Encrypt(plainToEncrypt, key, iv, aad)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) != expectedCipherLen {
		return nil, errors.New("加密输出长度不匹配")
	}

	skHeader := &ikev2.PayloadHeader{
		NextPayload:   nextPayload,
		PayloadLength: uint16(4 + len(iv) + len(ciphertext) + icvSize),
	}

	packet := append(aad, skHeader.Encode()...)
	packet = append(packet, iv...)
	packet = append(packet, ciphertext...)
	if !s.ikeIsAEAD && s.IntegAlg != nil {
		icv := s.IntegAlg.Compute(s.Keys.SK_ai, packet)
		packet = append(packet, icv...)
	}
	if uint32(len(packet)) != hdr.Length {
		return nil, errors.New("IKE 长度字段不匹配")
	}
	return packet, nil
}

func (s *Session) NextSequenceNumber() uint32 {
	s.SequenceNumber++
	return s.SequenceNumber - 1
}
