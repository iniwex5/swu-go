package swu

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/iniwex5/swu-go/pkg/crypto"
	"github.com/iniwex5/swu-go/pkg/ikev2"
	"github.com/iniwex5/swu-go/pkg/ipsec"
	"github.com/iniwex5/swu-go/pkg/logger"
)

// RekeyChildSA 执行 CHILD_SA 密钥轮换 (CREATE_CHILD_SA 交换)
// RFC 7296 1.3.3: 重新协商 CHILD_SA
func (s *Session) RekeyChildSA() error {
	if s.ChildSAOut == nil {
		return errors.New("没有活动的 CHILD_SA 可以 Rekey")
	}

	logger.Info("开始 CHILD_SA Rekey")

	// 1. 生成新的 Nonce
	newNonce, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}

	// 2. 生成新的 SPI
	newSPI, err := crypto.RandomBytes(4)
	if err != nil {
		return err
	}
	newSPIValue := binary.BigEndian.Uint32(newSPI)

	// 3. 构造 SA 载荷 (与 IKE_AUTH 中的 Child SA 相同)
	prop := ikev2.NewProposal(1, ikev2.ProtoESP, newSPI)
	prop.AddTransform(ikev2.TransformTypeEncr, ikev2.ENCR_AES_GCM_16, 128)
	prop.AddTransform(ikev2.TransformTypeESN, 0, 0)

	saPayload := &ikev2.EncryptedPayloadSA{
		Proposals: []*ikev2.Proposal{prop},
	}

	// 4. Nonce 载荷
	noncePayload := &ikev2.EncryptedPayloadNonce{NonceData: newNonce}

	// 5. REKEY_SA Notify (告知要 Rekey 哪个 SA)
	oldSPIBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(oldSPIBytes, s.ChildSAOut.SPI)
	rekeyNotify := &ikev2.EncryptedPayloadNotify{
		ProtocolID: ikev2.ProtoESP,
		SPI:        oldSPIBytes,
		NotifyType: ikev2.REKEY_SA,
	}

	// 6. TSi / TSr (保持不变，使用全流量)
	tsi := s.tsi
	tsr := s.tsr
	if len(tsi) == 0 || len(tsr) == 0 {
		ts := ikev2.NewTrafficSelectorIPV4(
			[]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255},
			0, 65535,
		)
		tsi = []*ikev2.TrafficSelector{ts}
		tsr = []*ikev2.TrafficSelector{ts}
	}
	tsPayloadI := &ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: tsi}
	tsPayloadR := &ikev2.EncryptedPayloadTS{IsInitiator: false, TrafficSelectors: tsr}

	// 7. 构造并发送 CREATE_CHILD_SA 请求
	payloads := []ikev2.Payload{saPayload, noncePayload, rekeyNotify, tsPayloadI, tsPayloadR}
	respData, err := s.sendEncryptedWithRetry(payloads, ikev2.CREATE_CHILD_SA)
	if err != nil {
		return fmt.Errorf("CREATE_CHILD_SA 失败: %v", err)
	}

	return s.handleCreateChildSAResp(respData, newNonce, newSPIValue)
}

// handleCreateChildSAResp 处理 CREATE_CHILD_SA 响应
func (s *Session) handleCreateChildSAResp(data []byte, niNonce []byte, newSPI uint32) error {
	_, payloads, err := s.decryptAndParse(data)
	if err != nil {
		return err
	}

	var respSA *ikev2.EncryptedPayloadSA
	var respNonce []byte
	var respSPI uint32
	var encrID uint16
	var encrKeyLenBits int

	for _, pl := range payloads {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadSA:
			respSA = p
			if len(p.Proposals) > 0 && len(p.Proposals[0].SPI) >= 4 {
				respSPI = binary.BigEndian.Uint32(p.Proposals[0].SPI)
			}
			if len(p.Proposals) > 0 {
				for _, t := range p.Proposals[0].Transforms {
					if t.Type == ikev2.TransformTypeEncr {
						encrID = uint16(t.ID)
						for _, a := range t.Attributes {
							if a.Type == ikev2.AttributeKeyLength {
								encrKeyLenBits = int(a.Val)
							}
						}
					}
				}
			}
		case *ikev2.EncryptedPayloadNonce:
			respNonce = p.NonceData
		case *ikev2.EncryptedPayloadNotify:
			if p.NotifyType < 16384 { // 错误通知
				return fmt.Errorf("CREATE_CHILD_SA 被拒绝，通知类型: %d", p.NotifyType)
			}
		}
	}

	if respSA == nil || respNonce == nil {
		return errors.New("CREATE_CHILD_SA 响应缺少必要的载荷")
	}
	if encrID == 0 {
		return errors.New("CREATE_CHILD_SA 响应缺少加密算法选择")
	}

	// 10. 派生新的 Child SA 密钥
	// KEYMAT = prf+(SK_d, Ni | Nr)
	childEnc, err := crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	if err != nil {
		return fmt.Errorf("不支持的 Child SA 加密算法: %d", encrID)
	}

	keyLen := childEnc.KeySize()
	saltLen := 4 // AES-GCM salt
	keyMatLen := 2 * (keyLen + saltLen)

	seed := make([]byte, 0, len(niNonce)+len(respNonce))
	seed = append(seed, niNonce...)
	seed = append(seed, respNonce...)

	keyMat, err := crypto.PrfPlus(s.PRFAlg, s.Keys.SK_d, seed, keyMatLen)
	if err != nil {
		return err
	}

	newSAOut := ipsec.NewSecurityAssociation(newSPI, childEnc, keyMat[0:keyLen+saltLen], nil)
	newSAOut.RemoteSPI = respSPI

	newSAIn := ipsec.NewSecurityAssociation(respSPI, childEnc, keyMat[keyLen+saltLen:2*(keyLen+saltLen)], nil)
	newSAIn.RemoteSPI = newSPI

	// 11. 删除旧 SA 并替换
	oldOutSPI := s.ChildSAOut.SPI
	s.ChildSAOut = newSAOut
	s.ChildSAIn = newSAIn
	if s.ChildSAsIn != nil {
		s.ChildSAsIn[respSPI] = newSAIn
	}
	if len(s.childOutPolicies) > 0 {
		s.childOutPolicies[0].saOut = newSAOut
	} else if len(s.tsr) > 0 {
		s.childOutPolicies = append(s.childOutPolicies, childOutPolicy{saOut: newSAOut, tsr: s.tsr})
	}
	if s.ws != nil {
		s.ws.LogChildSA(newSPI, respSPI, s.cfg.LocalAddr, s.cfg.EpDGAddr, keyMat[keyLen+saltLen:2*(keyLen+saltLen)], keyMat[0:keyLen+saltLen], encrID)
	}

	logger.Info("CHILD_SA Rekey 成功", logger.Uint32("oldSPI", oldOutSPI), logger.Uint32("newSPI", newSPI))

	// 12. 发送删除旧 SA 的通知 (可选但推荐)
	go func() {
		if err := s.sendDeleteChildSA([]uint32{oldOutSPI}); err != nil {
			logger.Warn("发送旧 Child SA Delete 通知失败", logger.Err(err))
		}
	}()

	return nil
}

// RekeyIKESA 执行 IKE SA 密钥轮换
// 这比 CHILD_SA Rekey 更复杂，需要重新协商 IKE SA
func (s *Session) RekeyIKESA() error {
	logger.Warn("IKE SA Rekey 目前不支持")
	return errors.New("IKE SA Rekey 尚未实现")
}
