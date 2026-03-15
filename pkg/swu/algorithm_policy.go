package swu

import (
	"fmt"
	"sort"
	"strings"

	"github.com/iniwex5/swu-go/pkg/crypto"
	"github.com/iniwex5/swu-go/pkg/ikev2"
)

const (
	AlgorithmPolicyStrict       = "strict"
	AlgorithmPolicyBalanced     = "balanced"
	AlgorithmPolicyLegacyPrefer = "legacy_prefer"

	ErrClassAlgorithmCapabilityMismatch = "algorithm_capability_mismatch"
	ErrClassAlgorithmPolicyRejected     = "algorithm_policy_rejected"
	ErrClassDriverUnsupported           = "driver_unsupported"
)

type NegotiationError struct {
	Class     string
	Reason    string
	Retryable bool
}

func (e *NegotiationError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Class, e.Reason)
}

type algorithmPlan struct {
	policy        string
	allowLegacy   bool
	allowedLegacy map[ikev2.AlgorithmType]bool
}

func buildAlgorithmPlan(cfg *Config) algorithmPlan {
	policy := normalizeAlgorithmPolicy(cfg.AlgorithmPolicy)
	allowLegacy := cfg.EnableLegacyCiphers && policy != AlgorithmPolicyStrict

	allowedLegacy := map[ikev2.AlgorithmType]bool{}
	if allowLegacy {
		if len(cfg.AllowedLegacyCiphers) == 0 {
			allowedLegacy[ikev2.ENCR_3DES] = true
			allowedLegacy[ikev2.ENCR_DES] = true
		} else {
			for _, raw := range cfg.AllowedLegacyCiphers {
				switch normalizeLegacyName(raw) {
				case "3des":
					allowedLegacy[ikev2.ENCR_3DES] = true
				case "des":
					allowedLegacy[ikev2.ENCR_DES] = true
				}
			}
		}
	}

	return algorithmPlan{
		policy:        policy,
		allowLegacy:   allowLegacy,
		allowedLegacy: allowedLegacy,
	}
}

func normalizeAlgorithmPolicy(raw string) string {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case AlgorithmPolicyStrict:
		return AlgorithmPolicyStrict
	case AlgorithmPolicyLegacyPrefer:
		return AlgorithmPolicyLegacyPrefer
	default:
		return AlgorithmPolicyBalanced
	}
}

func normalizeLegacyName(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	v = strings.ReplaceAll(v, "_", "")
	v = strings.ReplaceAll(v, "-", "")
	switch v {
	case "tripledes", "3des":
		return "3des"
	default:
		return v
	}
}

func (p algorithmPlan) allowsEncryption(alg ikev2.AlgorithmType) bool {
	if !isLegacyEncryption(alg) {
		return true
	}
	if p.policy == AlgorithmPolicyStrict {
		return false
	}
	return p.allowLegacy && p.allowedLegacy[alg]
}

func (p algorithmPlan) policyLabel() string {
	if p.policy == AlgorithmPolicyStrict {
		return AlgorithmPolicyStrict
	}
	if p.allowLegacy && p.policy == AlgorithmPolicyLegacyPrefer {
		return AlgorithmPolicyLegacyPrefer
	}
	if p.allowLegacy {
		return "balanced+legacy"
	}
	return AlgorithmPolicyBalanced
}

func (p algorithmPlan) effectiveAlgSetLabel() []string {
	out := []string{"aes_cbc", "aes_gcm", "sha1/sha2", "prf_sha1/sha2", "dh_modp/ecp"}
	if p.allowsEncryption(ikev2.ENCR_3DES) {
		out = append(out, "3des")
	}
	if p.allowsEncryption(ikev2.ENCR_DES) {
		out = append(out, "des")
	}
	sort.Strings(out)
	return out
}

func isLegacyEncryption(alg ikev2.AlgorithmType) bool {
	return alg == ikev2.ENCR_DES || alg == ikev2.ENCR_3DES
}

func isAEADEncryption(alg ikev2.AlgorithmType) bool {
	switch alg {
	case ikev2.ENCR_AES_GCM_8, ikev2.ENCR_AES_GCM_12, ikev2.ENCR_AES_GCM_16,
		ikev2.ENCR_AES_CCM_8, ikev2.ENCR_AES_CCM_12, ikev2.ENCR_AES_CCM_16:
		return true
	default:
		return false
	}
}

func supportedByCryptoFactory(encrID uint16, encrKeyLenBits int) bool {
	_, err := crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	return err == nil
}
