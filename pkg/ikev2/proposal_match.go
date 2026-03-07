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
			// 高安全现代组 (首选)
			ENCR_AES_GCM_16,
			ENCR_AES_GCM_12,
			ENCR_AES_GCM_8,
			ENCR_AES_CCM_16,
			// 主流组
			ENCR_AES_CBC,
			ENCR_AES_CTR,
			// 老旧兼容兜底
			ENCR_3DES,
		},
		SupportedInteg: []AlgorithmType{
			AUTH_NONE, // AEAD 不需要独立完整性
			// SHA-2 系列
			AUTH_HMAC_SHA2_512_256,
			AUTH_HMAC_SHA2_384_192,
			AUTH_HMAC_SHA2_256_128,
			// 老旧与兜底系列
			AUTH_AES_XCBC_96,
			AUTH_HMAC_SHA1_96,
		},
		SupportedPRF: []AlgorithmType{
			PRF_HMAC_SHA2_512,
			PRF_HMAC_SHA2_384,
			PRF_HMAC_SHA2_256,
			PRF_AES128_XCBC,
			PRF_HMAC_SHA1,
		},
		SupportedDH: []AlgorithmType{
			// 安全组
			ECP_384_bit,
			ECP_256_bit,
			MODP_4096_bit,
			MODP_3072_bit,
			MODP_2048_bit, // IKEv2 最普及的安全底线
			// 兜底组 (不推荐但有时必须)
			MODP_1536_bit,
			MODP_1024_bit,
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

// CreateMultiProposalIKE 创建涵盖高、中、低兼容级别的 IKE 提议
func CreateMultiProposalIKE(spi []byte) []*Proposal {
	// 兼容策略：
	// 1. 优先给出主流 HMAC-SHA2 组合
	// 2. 其次给出老旧但常见的 HMAC-SHA1
	// 3. 最后再回退到 AES-XCBC 族
	//
	// 这样可避免某些网络在“同一 Proposal 内含 XCBC”时直接选择 XCBC，
	// 同时保留对仅支持 XCBC 的旧式 ePDG/AAA 设备的兼容能力。
	makeProp := func(num uint8, integ, prf AlgorithmType) *Proposal {
		prop := NewProposal(num, ProtoIKE, spi)
		prop.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 128)
		prop.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 256)
		prop.AddTransform(TransformTypeInteg, integ, 0)
		prop.AddTransform(TransformTypePRF, prf, 0)
		prop.AddTransform(TransformTypeDH, MODP_1024_bit, 0)
		prop.AddTransform(TransformTypeDH, MODP_1536_bit, 0)
		prop.AddTransform(TransformTypeDH, MODP_2048_bit, 0)
		// 保持原有首发兼容顺序不变，只追加 MODP3072 以提升对更现代 ePDG 的兼容性。
		prop.AddTransform(TransformTypeDH, MODP_3072_bit, 0)
		// 再追加 ECP 组，作为更现代网络的兼容项，但不改变现有 MODP 首发顺序。
		prop.AddTransform(TransformTypeDH, ECP_256_bit, 0)
		prop.AddTransform(TransformTypeDH, ECP_384_bit, 0)
		return prop
	}
	return []*Proposal{
		makeProp(1, AUTH_HMAC_SHA2_256_128, PRF_HMAC_SHA2_256),
		makeProp(2, AUTH_HMAC_SHA1_96, PRF_HMAC_SHA1),
		makeProp(3, AUTH_AES_XCBC_96, PRF_AES128_XCBC),
	}
}

// CreateMultiProposalESP 创建涵盖高、中、低兼容级别的 ESP 提议
func CreateMultiProposalESP(spi []byte) []*Proposal {
	proposals := []*Proposal{}
	pNum := uint8(1)

	// 提议 1: 高安全 (AES-GCM-256)
	prop1 := NewProposal(pNum, ProtoESP, spi)
	prop1.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_GCM_16, 256)
	prop1.AddTransform(TransformTypeESN, 0, 0)
	proposals = append(proposals, prop1)
	pNum++

	// 提议 2: 主流安全 (AES-GCM-128)
	prop2 := NewProposal(pNum, ProtoESP, spi)
	prop2.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_GCM_16, 128)
	prop2.AddTransform(TransformTypeESN, 0, 0)
	proposals = append(proposals, prop2)
	pNum++

	// 提议 3: 传统主流 (AES-CBC-128 + SHA256)
	prop3 := NewProposal(pNum, ProtoESP, spi)
	prop3.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 128)
	prop3.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0)
	prop3.AddTransform(TransformTypeESN, 0, 0)
	proposals = append(proposals, prop3)
	pNum++

	// 提议 4: 远古兜底兼容组 (AES-CBC-128 + SHA1)
	prop4 := NewProposal(pNum, ProtoESP, spi)
	prop4.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 128)
	prop4.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA1_96, 0)
	prop4.AddTransform(TransformTypeESN, 0, 0)
	proposals = append(proposals, prop4)

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
