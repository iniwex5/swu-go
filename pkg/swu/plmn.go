package swu

import (
	"fmt"
	"strings"
)

func normalizeMNC(mnc string) string {
	if len(mnc) == 2 {
		return "0" + mnc
	}
	return mnc
}

func normalizeMCC(mcc string) string {
	return mcc
}

func effectiveMCCMNC(imsi string, cfg *Config) (string, string) {
	mcc := ""
	mnc := ""
	if len(imsi) >= 5 {
		mcc = imsi[0:3]
		mnc = imsi[3:5]
	}
	if cfg.MCC != "" {
		mcc = cfg.MCC
	}
	if cfg.MNC != "" {
		mnc = cfg.MNC
	}
	return normalizeMCC(mcc), normalizeMNC(mnc)
}

func buildNAI(imsi string, cfg *Config) string {
	mcc, mnc := effectiveMCCMNC(imsi, cfg)
	return fmt.Sprintf("0%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org", imsi, mnc, mcc)
}

func buildIKENAI(imsi string, cfg *Config) string {
	mcc, mnc := effectiveMCCMNC(imsi, cfg)
	return fmt.Sprintf("0%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org", imsi, mnc, mcc)
}

func buildIKEWLANNAI(imsi string, cfg *Config) string {
	mcc, mnc := effectiveMCCMNC(imsi, cfg)
	return fmt.Sprintf("0%s@wlan.mnc%s.mcc%s.3gppnetwork.org", imsi, mnc, mcc)
}

func buildWLANNAI(imsi string, cfg *Config) string {
	mcc, mnc := effectiveMCCMNC(imsi, cfg)
	return fmt.Sprintf("0%s@wlan.mnc%s.mcc%s.3gppnetwork.org", imsi, mnc, mcc)
}

func buildAKAPrimeNAI(imsi string, cfg *Config) string {
	mcc, mnc := effectiveMCCMNC(imsi, cfg)
	return fmt.Sprintf("6%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org", imsi, mnc, mcc)
}

func buildAKAPrimeWLANNAI(imsi string, cfg *Config) string {
	mcc, mnc := effectiveMCCMNC(imsi, cfg)
	return fmt.Sprintf("6%s@wlan.mnc%s.mcc%s.3gppnetwork.org", imsi, mnc, mcc)
}

func buildAKAIdentity(imsi string, cfg *Config) string {
	// Align with Android iWLAN default behavior: always use EPC NAI style identity.
	return buildNAI(imsi, cfg)
}

// buildInitialEAPIdentity 构造协商前的 EAP Identity (Type=1)。
// 当本地偏好 AKA' 时，使用 6 前缀主动表达 AKA' 能力，提升服务端选择 Type=50 的概率。
func buildInitialEAPIdentity(imsi string, cfg *Config) string {
	if cfg != nil && cfg.AKAPrimePreferred {
		return buildAKAPrimeNAI(imsi, cfg)
	}
	return buildAKAIdentity(imsi, cfg)
}

func buildIKEIdentity(imsi string, cfg *Config) string {
	// 当配置了 AKAPrimePreferred 时，IKE IDi 使用 "6" 前缀 NAI，
	// 主动向 AAA 声明客户端期望 EAP-AKA'（而非默认的 EAP-AKA）。
	if cfg.AKAPrimePreferred {
		return buildAKAPrimeNAI(imsi, cfg)
	}
	// Align with Android iWLAN default behavior: always use EPC NAI style identity.
	return buildIKENAI(imsi, cfg)
}

func buildAKAIdentityForEAPType(imsi string, cfg *Config, eapType uint8) string {
	// 互通优先:
	// 某些运营商在 EAP-AKA' (Type=50) 下仍要求 Permanent Identity 使用 0 前缀 EPC NAI，
	// 当运营商画像指定 AKAIdentityMode=epc_nai 时，显式保持 0 前缀，避免 Identity 阶段被 AAA 拒绝。
	if cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.AKAIdentityMode), "epc_nai") {
		return buildAKAIdentity(imsi, cfg)
	}
	// 其余场景保持随 EAP 类型自适配：AKA' 使用 6 前缀。
	if eapType == 50 {
		return buildAKAPrimeNAI(imsi, cfg)
	}
	return buildAKAIdentity(imsi, cfg)
}
