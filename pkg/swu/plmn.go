package swu

import "fmt"

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
	// 当服务端使用 EAP-AKA' (type=50) 时，自动使用 "6" 前缀 NAI (3GPP TS 23.003 §19.3)
	// 不再依赖 AKAPrimePreferred 配置——始终跟随服务端协商的 EAP Type 自动适配
	if eapType == 50 {
		return buildAKAPrimeNAI(imsi, cfg)
	}
	return buildAKAIdentity(imsi, cfg)
}
