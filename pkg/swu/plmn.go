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
	switch cfg.AKAIdentityMode {
	case "imsi_only":
		return "0" + imsi
	case "wlan_nai":
		return buildWLANNAI(imsi, cfg)
	case "epc_nai":
		return buildNAI(imsi, cfg)
	default:
		return buildNAI(imsi, cfg)
	}
}

func buildIKEIdentity(imsi string, cfg *Config) string {
	switch cfg.IKEIdentityMode {
	case "imsi_only":
		return "0" + imsi
	case "wlan_nai":
		return buildIKEWLANNAI(imsi, cfg)
	case "epc_nai", "":
		return buildIKENAI(imsi, cfg)
	default:
		return buildIKENAI(imsi, cfg)
	}
}

func buildAKAIdentityForEAPType(imsi string, cfg *Config, eapType uint8) string {
	if eapType == 50 && cfg != nil && cfg.AKAPrimePreferred {
		switch cfg.AKAIdentityMode {
		case "imsi_only":
			return "6" + imsi
		case "wlan_nai":
			return buildAKAPrimeWLANNAI(imsi, cfg)
		case "epc_nai", "":
			return buildAKAPrimeNAI(imsi, cfg)
		default:
			return buildAKAPrimeNAI(imsi, cfg)
		}
	}
	return buildAKAIdentity(imsi, cfg)
}
