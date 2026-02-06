package ikev2

// ProposalMatcher 用于多提议协商
// 根据本地支持的算法列表，从响应中选择最佳匹配
type ProposalMatcher struct {
	// 支持的加密算法 (按优先级排序)
	SupportedEncr []AlgorithmType
	// 支持的完整性算法
	SupportedInteg []AlgorithmType
	// 支持的 PRF 算法
	SupportedPRF []AlgorithmType
	// 支持的 DH 组
	SupportedDH []AlgorithmType
}

// DefaultProposalMatcher 返回默认的算法优先级
func DefaultProposalMatcher() *ProposalMatcher {
	return &ProposalMatcher{
		SupportedEncr: []AlgorithmType{
			ENCR_AES_GCM_16, // 首选 AEAD
			ENCR_AES_GCM_12,
			ENCR_AES_GCM_8,
			ENCR_AES_CBC, // 回退到 CBC
		},
		SupportedInteg: []AlgorithmType{
			AUTH_NONE, // AEAD 不需要独立完整性
			AUTH_HMAC_SHA2_256_128,
			AUTH_HMAC_SHA2_512_256,
			AUTH_HMAC_SHA1_96,
		},
		SupportedPRF: []AlgorithmType{
			PRF_HMAC_SHA2_256,
			PRF_HMAC_SHA2_512,
			PRF_HMAC_SHA1,
		},
		SupportedDH: []AlgorithmType{
			MODP_2048_bit,
			MODP_3072_bit,
			MODP_4096_bit,
		},
	}
}

// MatchedAlgorithms 匹配结果
type MatchedAlgorithms struct {
	ProposalNum uint8
	ProtocolID  ProtocolID
	SPI         []byte
	Encr        AlgorithmType
	EncrKeyLen  uint16 // 从属性中获取
	Integ       AlgorithmType
	PRF         AlgorithmType
	DH          AlgorithmType
}

// SelectBestProposal 从 SA 中选择最佳匹配的提议
func (pm *ProposalMatcher) SelectBestProposal(sa *EncryptedPayloadSA) (*MatchedAlgorithms, error) {
	for _, prop := range sa.Proposals {
		matched := pm.matchProposal(prop)
		if matched != nil {
			return matched, nil
		}
	}
	return nil, nil // 无匹配
}

func (pm *ProposalMatcher) matchProposal(prop *Proposal) *MatchedAlgorithms {
	result := &MatchedAlgorithms{
		ProposalNum: prop.ProposalNum,
		ProtocolID:  prop.ProtocolID,
		SPI:         prop.SPI,
	}

	// 按变换类型分组
	encrFound := false
	integFound := false
	prfFound := false
	dhFound := false

	for _, t := range prop.Transforms {
		switch t.Type {
		case TransformTypeEncr:
			if pm.containsAlg(pm.SupportedEncr, t.ID) {
				result.Encr = t.ID
				encrFound = true
				// 提取密钥长度属性
				for _, attr := range t.Attributes {
					if attr.Type == AttributeKeyLength {
						result.EncrKeyLen = attr.Val
					}
				}
			}
		case TransformTypeInteg:
			if pm.containsAlg(pm.SupportedInteg, t.ID) {
				result.Integ = t.ID
				integFound = true
			}
		case TransformTypePRF:
			if pm.containsAlg(pm.SupportedPRF, t.ID) {
				result.PRF = t.ID
				prfFound = true
			}
		case TransformTypeDH:
			if pm.containsAlg(pm.SupportedDH, t.ID) {
				result.DH = t.ID
				dhFound = true
			}
		case TransformTypeESN:
			// ESN 通常接受 0 (不使用) 或 1 (使用)
		}
	}

	// IKE SA 需要: ENCR, PRF, (INTEG for non-AEAD), DH
	// Child SA (ESP) 需要: ENCR, (INTEG for non-AEAD), (ESN)
	if prop.ProtocolID == ProtoIKE {
		if encrFound && prfFound && dhFound {
			// AEAD 不需要独立的 INTEG
			if pm.isAEAD(result.Encr) || integFound {
				return result
			}
		}
	} else if prop.ProtocolID == ProtoESP {
		if encrFound {
			if pm.isAEAD(result.Encr) || integFound {
				return result
			}
		}
	}

	return nil
}

func (pm *ProposalMatcher) containsAlg(list []AlgorithmType, alg AlgorithmType) bool {
	for _, a := range list {
		if a == alg {
			return true
		}
	}
	return false
}

func (pm *ProposalMatcher) isAEAD(encr AlgorithmType) bool {
	switch encr {
	case ENCR_AES_GCM_8, ENCR_AES_GCM_12, ENCR_AES_GCM_16,
		ENCR_AES_CCM_8, ENCR_AES_CCM_12, ENCR_AES_CCM_16:
		return true
	default:
		return false
	}
}

// CreateMultiProposalIKE 创建多个 IKE 提议
func CreateMultiProposalIKE(spi []byte) []*Proposal {
	proposals := []*Proposal{}

	// 提议 1: AES-GCM-256 + SHA256 + DH14
	prop1 := NewProposal(1, ProtoIKE, spi)
	prop1.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_GCM_16, 256)
	prop1.AddTransform(TransformTypePRF, PRF_HMAC_SHA2_256, 0)
	prop1.AddTransform(TransformTypeDH, MODP_2048_bit, 0)
	proposals = append(proposals, prop1)

	// 提议 2: AES-GCM-128 + SHA256 + DH14
	prop2 := NewProposal(2, ProtoIKE, spi)
	prop2.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_GCM_16, 128)
	prop2.AddTransform(TransformTypePRF, PRF_HMAC_SHA2_256, 0)
	prop2.AddTransform(TransformTypeDH, MODP_2048_bit, 0)
	proposals = append(proposals, prop2)

	// 提议 3: AES-CBC-256 + HMAC-SHA256 + SHA256 + DH14
	prop3 := NewProposal(3, ProtoIKE, spi)
	prop3.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 256)
	prop3.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0)
	prop3.AddTransform(TransformTypePRF, PRF_HMAC_SHA2_256, 0)
	prop3.AddTransform(TransformTypeDH, MODP_2048_bit, 0)
	proposals = append(proposals, prop3)

	return proposals
}

// CreateMultiProposalESP 创建多个 ESP 提议
func CreateMultiProposalESP(spi []byte) []*Proposal {
	proposals := []*Proposal{}

	// 提议 1: AES-GCM-128, NO_ESN
	prop1 := NewProposal(1, ProtoESP, spi)
	prop1.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_GCM_16, 128)
	prop1.AddTransform(TransformTypeESN, 0, 0) // NO_ESN
	proposals = append(proposals, prop1)

	// 提议 2: AES-CBC-128 + HMAC-SHA1-96
	prop2 := NewProposal(2, ProtoESP, spi)
	prop2.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 128)
	prop2.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA1_96, 0)
	prop2.AddTransform(TransformTypeESN, 0, 0)
	proposals = append(proposals, prop2)

	return proposals
}

// AddTransformWithKeyLen 添加带密钥长度属性的变换
func (p *Proposal) AddTransformWithKeyLen(tType TransformType, tID AlgorithmType, keyLen int) {
	t := &Transform{
		Type: tType,
		ID:   tID,
	}
	if keyLen > 0 {
		t.Attributes = append(t.Attributes, &TransformAttribute{
			Type: AttributeKeyLength,
			Val:  uint16(keyLen),
		})
	}
	p.Transforms = append(p.Transforms, t)
}
