package swu

import (
	"encoding/binary"
	"fmt"

	"github.com/iniwex5/swu-go/pkg/crypto"
	"github.com/iniwex5/swu-go/pkg/ikev2"
	"github.com/iniwex5/swu-go/pkg/ipsec"
	"github.com/iniwex5/swu-go/pkg/logger"
)

func (s *Session) ensureIKEDispatcher() {
	s.ikeMu.Lock()
	if s.ikeStarted {
		s.ikeMu.Unlock()
		return
	}
	s.ikeStarted = true
	s.ikeMu.Unlock()

	go s.ikeDispatchLoop()
}

func (s *Session) startIKEControlLoop() {
	s.ikeMu.Lock()
	s.ikeControlAlive = true
	s.ikeMu.Unlock()
	s.ensureIKEDispatcher()
}

func (s *Session) ikeDispatchLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case data, ok := <-s.socket.IKEPackets():
			if !ok {
				return
			}

			hdr, err := ikev2.DecodeHeader(data)
			if err != nil {
				continue
			}

			if hdr.Flags&ikev2.FlagResponse != 0 {
				key := ikeWaitKey{exchangeType: hdr.ExchangeType, msgID: hdr.MessageID}
				s.ikeMu.Lock()
				ch := s.ikeWaiters[key]
				if ch == nil && s.ikePending != nil {
					s.ikePending[key] = data
				}
				s.ikeMu.Unlock()
				if ch != nil {
					select {
					case ch <- data:
					default:
					}
				}
				continue
			}

			s.ikeMu.Lock()
			active := s.ikeControlAlive
			s.ikeMu.Unlock()
			if !active {
				continue
			}

			switch hdr.ExchangeType {
			case ikev2.INFORMATIONAL:
				if err := s.handleIncomingInformational(data); err != nil {
					logger.Warn("处理 INFORMATIONAL 失败", logger.Err(err))
				}
			case ikev2.CREATE_CHILD_SA:
				if err := s.handleIncomingCreateChildSA(data); err != nil {
					logger.Warn("处理 CREATE_CHILD_SA 失败", logger.Err(err))
				}
			}
		}
	}
}

func (s *Session) sendEncryptedResponseWithMsgID(payloads []ikev2.Payload, exchangeType ikev2.ExchangeType, msgID uint32) error {
	packet, err := s.encryptAndWrapWithMsgID(payloads, exchangeType, msgID, true)
	if err != nil {
		return err
	}
	return s.socket.SendIKE(packet)
}

func (s *Session) handleIncomingInformational(data []byte) error {
	msgID, payloads, err := s.decryptAndParse(data)
	if err != nil {
		return err
	}

	for _, pl := range payloads {
		del, ok := pl.(*ikev2.EncryptedPayloadDelete)
		if !ok {
			continue
		}

		if del.ProtocolID == ikev2.ProtoIKE {
			if s.cancel != nil {
				s.cancel()
			}
			continue
		}

		if del.ProtocolID != ikev2.ProtoESP || del.SPISize != 4 {
			continue
		}

		for i := 0; i+4 <= len(del.SPIs); i += 4 {
			spi := binary.BigEndian.Uint32(del.SPIs[i : i+4])
			if s.ChildSAsIn != nil {
				delete(s.ChildSAsIn, spi)
			}
			if s.ChildSAOut != nil && s.ChildSAOut.SPI == spi {
				s.ChildSAOut = nil
				if len(s.childOutPolicies) > 0 {
					s.childOutPolicies[0].saOut = nil
				}
			}
		}
	}

	return s.sendEncryptedResponseWithMsgID(nil, ikev2.INFORMATIONAL, msgID)
}

func (s *Session) handleIncomingCreateChildSA(data []byte) error {
	msgID, payloads, err := s.decryptAndParse(data)
	if err != nil {
		return err
	}

	var reqSA *ikev2.EncryptedPayloadSA
	var reqNonce []byte
	var peerSPI uint32
	var encrID uint16
	var tsi []*ikev2.TrafficSelector
	var tsr []*ikev2.TrafficSelector

	for _, pl := range payloads {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadSA:
			reqSA = p
			if len(p.Proposals) > 0 && len(p.Proposals[0].SPI) >= 4 {
				peerSPI = binary.BigEndian.Uint32(p.Proposals[0].SPI)
			}
			if len(p.Proposals) > 0 {
				for _, t := range p.Proposals[0].Transforms {
					if t.Type == ikev2.TransformTypeEncr {
						encrID = uint16(t.ID)
					}
				}
			}
		case *ikev2.EncryptedPayloadNonce:
			reqNonce = p.NonceData
		case *ikev2.EncryptedPayloadTS:
			if p.IsInitiator {
				tsi = p.TrafficSelectors
			} else {
				tsr = p.TrafficSelectors
			}
		case *ikev2.EncryptedPayloadNotify:
			if p.NotifyType < 16384 {
				return fmt.Errorf("CREATE_CHILD_SA 错误通知: %d", p.NotifyType)
			}
		}
	}

	if reqSA == nil || len(reqNonce) == 0 || peerSPI == 0 || encrID == 0 {
		return fmt.Errorf("CREATE_CHILD_SA 请求缺少必要载荷")
	}

	nr, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}
	spiBytes, err := crypto.RandomBytes(4)
	if err != nil {
		return err
	}
	ourSPI := binary.BigEndian.Uint32(spiBytes)

	var encrKeyLenBits int
	for _, t := range reqSA.Proposals[0].Transforms {
		if t.Type == ikev2.TransformTypeEncr {
			for _, a := range t.Attributes {
				if a.Type == ikev2.AttributeKeyLength {
					encrKeyLenBits = int(a.Val)
				}
			}
		}
	}
	childEnc, err := crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	if err != nil {
		return fmt.Errorf("不支持的 Child SA 加密算法: %d", encrID)
	}
	keyLen := childEnc.KeySize()
	saltLen := 4
	keyMatLen := 2 * (keyLen + saltLen)

	seed := make([]byte, 0, len(reqNonce)+len(nr))
	seed = append(seed, reqNonce...)
	seed = append(seed, nr...)

	keyMat, err := crypto.PrfPlus(s.PRFAlg, s.Keys.SK_d, seed, keyMatLen)
	if err != nil {
		return err
	}

	outKey := keyMat[0 : keyLen+saltLen]
	inKey := keyMat[keyLen+saltLen : 2*(keyLen+saltLen)]

	outSA := ipsec.NewSecurityAssociation(ourSPI, childEnc, outKey, nil)
	outSA.RemoteSPI = peerSPI

	inSA := ipsec.NewSecurityAssociation(peerSPI, childEnc, inKey, nil)
	inSA.RemoteSPI = ourSPI

	if s.ChildSAsIn != nil {
		s.ChildSAsIn[peerSPI] = inSA
	}

	if len(tsr) > 0 {
		pol := childOutPolicy{saOut: outSA, tsr: tsr}
		s.childOutPolicies = append([]childOutPolicy{pol}, s.childOutPolicies...)
	}

	if s.ws != nil {
		s.ws.LogChildSA(ourSPI, peerSPI, s.cfg.LocalAddr, s.cfg.EpDGAddr, inKey, outKey, encrID)
	}

	respProp := ikev2.NewProposal(1, ikev2.ProtoESP, spiBytes)
	respProp.AddTransform(ikev2.TransformTypeEncr, ikev2.AlgorithmType(encrID), 128)
	respProp.AddTransform(ikev2.TransformTypeESN, 0, 0)
	respSA := &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{respProp}}

	respNonce := &ikev2.EncryptedPayloadNonce{NonceData: nr}

	var respPayloads []ikev2.Payload
	respPayloads = append(respPayloads, respSA, respNonce)
	if len(tsi) > 0 {
		respPayloads = append(respPayloads, &ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: tsi})
	}
	if len(tsr) > 0 {
		respPayloads = append(respPayloads, &ikev2.EncryptedPayloadTS{IsInitiator: false, TrafficSelectors: tsr})
	}

	return s.sendEncryptedResponseWithMsgID(respPayloads, ikev2.CREATE_CHILD_SA, msgID)
}
