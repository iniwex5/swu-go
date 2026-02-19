package swu

import (
	"encoding/binary"
	"time"

	"github.com/iniwex5/swu-go/pkg/ikev2"
	"github.com/iniwex5/swu-go/pkg/logger"
)

// sendDPD 发送 Dead Peer Detection 请求
func (s *Session) sendDPD() error {
	s.Logger.Debug("发送 DPD 请求")
	_, err := s.sendEncryptedWithRetry(nil, ikev2.INFORMATIONAL)
	return err
}

// sendDeleteIKE 发送 IKE SA 删除通知
func (s *Session) sendDeleteIKE() error {
	s.Logger.Debug("发送 IKE SA Delete 通知")
	del := &ikev2.EncryptedPayloadDelete{
		ProtocolID: ikev2.ProtoIKE,
		SPISize:    0,
		NumSPIs:    0,
		SPIs:       nil,
	}
	pkt, err := s.encryptAndWrap([]ikev2.Payload{del}, ikev2.INFORMATIONAL, false)
	if err != nil {
		return err
	}
	return s.socket.SendIKE(pkt)
}

// sendDeleteChildSA 发送 Child SA 删除通知
func (s *Session) sendDeleteChildSA(spis []uint32) error {
	s.Logger.Debug("发送 Child SA Delete 通知", logger.Int("count", len(spis)))
	if len(spis) == 0 {
		return nil
	}
	raw := make([]byte, 0, 4*len(spis))
	for _, spi := range spis {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, spi)
		raw = append(raw, b...)
	}
	del := &ikev2.EncryptedPayloadDelete{
		ProtocolID: ikev2.ProtoESP,
		SPISize:    4,
		NumSPIs:    uint16(len(spis)),
		SPIs:       raw,
	}
	pkt, err := s.encryptAndWrap([]ikev2.Payload{del}, ikev2.INFORMATIONAL, false)
	if err != nil {
		return err
	}
	return s.socket.SendIKE(pkt)
}

// StartDPD 启动 DPD 后台任务
// 连续 dpdMaxFail 次失败触发 session down
func (s *Session) StartDPD(interval time.Duration) {
	const dpdMaxFail = 3

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		failCount := 0

		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				if err := s.sendDPD(); err != nil {
					failCount++
					s.Logger.Warn("DPD 发送失败",
						logger.Err(err),
						logger.Int("连续失败", failCount))

					if failCount >= dpdMaxFail {
						s.Logger.Error("DPD 连续失败达上限，判定对端不可达",
							logger.Int("maxFail", dpdMaxFail))
						if s.OnSessionDown != nil {
							go s.OnSessionDown()
						} else if s.cancel != nil {
							s.cancel()
						}
						return
					}
				} else {
					if failCount > 0 {
						s.Logger.Info("DPD 恢复正常", logger.Int("之前连续失败", failCount))
					}
					failCount = 0
				}
			}
		}
	}()
}
