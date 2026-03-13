package swu

import (
	"fmt"
	"strings"

	"github.com/iniwex5/swu-go/pkg/ikev2"
)

func configuredIKEProposalSummary(cfg []string) []string {
	if len(cfg) == 0 {
		return []string{"default-multi-proposal"}
	}
	return append([]string(nil), cfg...)
}

func configuredESPProposalSummary(cfg []string) []string {
	if len(cfg) == 0 {
		return []string{"default-multi-proposal"}
	}
	return append([]string(nil), cfg...)
}

type encrSpec struct {
	alg    ikev2.AlgorithmType
	keyLen int
	aead   bool
}

func buildIKEProposals(cfg []string, spi []byte) ([]*ikev2.Proposal, error) {
	if len(cfg) == 0 {
		return ikev2.CreateMultiProposalIKE(spi), nil
	}
	props := make([]*ikev2.Proposal, 0, len(cfg))
	for i, raw := range cfg {
		p, err := parseIKEProposal(raw, uint8(i+1), spi)
		if err != nil {
			return nil, err
		}
		props = append(props, p)
	}
	return props, nil
}

func buildESPProposals(cfg []string, spi []byte) ([]*ikev2.Proposal, error) {
	if len(cfg) == 0 {
		return ikev2.CreateMultiProposalESP(spi), nil
	}
	props := make([]*ikev2.Proposal, 0, len(cfg))
	for i, raw := range cfg {
		p, err := parseESPProposal(raw, uint8(i+1), spi)
		if err != nil {
			return nil, err
		}
		props = append(props, p)
	}
	return props, nil
}

func firstDHGroupFromProposals(props []*ikev2.Proposal) ikev2.AlgorithmType {
	for _, p := range props {
		for _, t := range p.Transforms {
			if t.Type == ikev2.TransformTypeDH {
				return t.ID
			}
		}
	}
	return ikev2.MODP_2048_bit
}

func parseIKEProposal(raw string, num uint8, spi []byte) (*ikev2.Proposal, error) {
	s := normalizeProposal(raw)
	if s == "" {
		return nil, fmt.Errorf("empty IKE proposal")
	}
	if s == "sunriselegacyandroid" {
		prop := ikev2.NewProposal(num, ikev2.ProtoIKE, spi)
		prop.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 128)
		prop.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 256)
		prop.AddTransform(ikev2.TransformTypeEncr, ikev2.ENCR_3DES, 0)
		prop.AddTransform(ikev2.TransformTypeEncr, ikev2.ENCR_DES, 0)
		prop.AddTransform(ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA1_96, 0)
		prop.AddTransform(ikev2.TransformTypePRF, ikev2.PRF_HMAC_SHA1, 0)
		prop.AddTransform(ikev2.TransformTypeDH, ikev2.MODP_1024_bit, 0)
		return prop, nil
	}

	parts := strings.Split(s, "-")
	if len(parts) != 3 && len(parts) != 4 {
		return nil, fmt.Errorf("invalid IKE proposal %q, expected 3 or 4 parts", raw)
	}

	encr, err := parseEncr(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid IKE proposal %q: %w", raw, err)
	}

	prop := ikev2.NewProposal(num, ikev2.ProtoIKE, spi)
	prop.AddTransformWithKeyLen(ikev2.TransformTypeEncr, encr.alg, encr.keyLen)

	var integ ikev2.AlgorithmType
	var prf ikev2.AlgorithmType
	var dh ikev2.AlgorithmType

	if len(parts) == 3 {
		if encr.aead {
			prf, err = parsePRF(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid IKE proposal %q: %w", raw, err)
			}
		} else {
			integ, err = parseInteg(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid IKE proposal %q: %w", raw, err)
			}
			prf = integToPRF(integ)
		}
		dh, err = parseDH(parts[2])
		if err != nil {
			return nil, fmt.Errorf("invalid IKE proposal %q: %w", raw, err)
		}
	} else {
		if encr.aead {
			prf, err = parsePRF(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid IKE proposal %q: %w", raw, err)
			}
			dh, err = parseDH(parts[2])
			if err != nil {
				return nil, fmt.Errorf("invalid IKE proposal %q: %w", raw, err)
			}
		} else {
			integ, err = parseInteg(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid IKE proposal %q: %w", raw, err)
			}
			prf, err = parsePRF(parts[2])
			if err != nil {
				return nil, fmt.Errorf("invalid IKE proposal %q: %w", raw, err)
			}
			dh, err = parseDH(parts[3])
			if err != nil {
				return nil, fmt.Errorf("invalid IKE proposal %q: %w", raw, err)
			}
		}
	}

	if !encr.aead {
		prop.AddTransform(ikev2.TransformTypeInteg, integ, 0)
	}
	prop.AddTransform(ikev2.TransformTypePRF, prf, 0)
	prop.AddTransform(ikev2.TransformTypeDH, dh, 0)
	return prop, nil
}

func parseESPProposal(raw string, num uint8, spi []byte) (*ikev2.Proposal, error) {
	s := normalizeProposal(raw)
	if s == "" {
		return nil, fmt.Errorf("empty ESP proposal")
	}
	parts := strings.Split(s, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return nil, fmt.Errorf("invalid ESP proposal %q, expected 1 or 2 parts", raw)
	}

	encr, err := parseEncr(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid ESP proposal %q: %w", raw, err)
	}

	prop := ikev2.NewProposal(num, ikev2.ProtoESP, spi)
	prop.AddTransformWithKeyLen(ikev2.TransformTypeEncr, encr.alg, encr.keyLen)

	if !encr.aead {
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid ESP proposal %q: missing integrity algorithm", raw)
		}
		integ, err := parseInteg(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid ESP proposal %q: %w", raw, err)
		}
		prop.AddTransform(ikev2.TransformTypeInteg, integ, 0)
	}
	prop.AddTransform(ikev2.TransformTypeESN, 0, 0)
	return prop, nil
}

func normalizeProposal(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func parseEncr(v string) (encrSpec, error) {
	switch v {
	case "aes128":
		return encrSpec{alg: ikev2.ENCR_AES_CBC, keyLen: 128, aead: false}, nil
	case "aes256":
		return encrSpec{alg: ikev2.ENCR_AES_CBC, keyLen: 256, aead: false}, nil
	case "3des":
		return encrSpec{alg: ikev2.ENCR_3DES, keyLen: 0, aead: false}, nil
	case "des":
		return encrSpec{alg: ikev2.ENCR_DES, keyLen: 0, aead: false}, nil
	case "aes128gcm16":
		return encrSpec{alg: ikev2.ENCR_AES_GCM_16, keyLen: 128, aead: true}, nil
	case "aes256gcm16":
		return encrSpec{alg: ikev2.ENCR_AES_GCM_16, keyLen: 256, aead: true}, nil
	default:
		return encrSpec{}, fmt.Errorf("unsupported encryption %q", v)
	}
}

func parseInteg(v string) (ikev2.AlgorithmType, error) {
	switch v {
	case "sha1":
		return ikev2.AUTH_HMAC_SHA1_96, nil
	case "sha256":
		return ikev2.AUTH_HMAC_SHA2_256_128, nil
	case "sha384":
		return ikev2.AUTH_HMAC_SHA2_384_192, nil
	case "sha512":
		return ikev2.AUTH_HMAC_SHA2_512_256, nil
	default:
		return 0, fmt.Errorf("unsupported integrity %q", v)
	}
}

func parsePRF(v string) (ikev2.AlgorithmType, error) {
	switch strings.TrimPrefix(v, "prf") {
	case "sha1":
		return ikev2.PRF_HMAC_SHA1, nil
	case "sha256":
		return ikev2.PRF_HMAC_SHA2_256, nil
	case "sha384":
		return ikev2.PRF_HMAC_SHA2_384, nil
	case "sha512":
		return ikev2.PRF_HMAC_SHA2_512, nil
	default:
		return 0, fmt.Errorf("unsupported prf %q", v)
	}
}

func parseDH(v string) (ikev2.AlgorithmType, error) {
	switch v {
	case "modp1024":
		return ikev2.MODP_1024_bit, nil
	case "modp1536":
		return ikev2.MODP_1536_bit, nil
	case "modp2048":
		return ikev2.MODP_2048_bit, nil
	case "modp3072":
		return ikev2.MODP_3072_bit, nil
	case "modp4096":
		return ikev2.MODP_4096_bit, nil
	case "ecp256":
		return ikev2.ECP_256_bit, nil
	case "ecp384":
		return ikev2.ECP_384_bit, nil
	default:
		return 0, fmt.Errorf("unsupported dh group %q", v)
	}
}

func integToPRF(v ikev2.AlgorithmType) ikev2.AlgorithmType {
	switch v {
	case ikev2.AUTH_HMAC_SHA1_96:
		return ikev2.PRF_HMAC_SHA1
	case ikev2.AUTH_HMAC_SHA2_384_192:
		return ikev2.PRF_HMAC_SHA2_384
	case ikev2.AUTH_HMAC_SHA2_512_256:
		return ikev2.PRF_HMAC_SHA2_512
	default:
		return ikev2.PRF_HMAC_SHA2_256
	}
}
