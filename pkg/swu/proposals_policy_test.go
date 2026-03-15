package swu

import (
	"testing"

	"github.com/iniwex5/swu-go/pkg/crypto"
	"github.com/iniwex5/swu-go/pkg/ikev2"
)

func TestBuildIKEProposalsSunriseLegacyDisabled(t *testing.T) {
	cfg := &Config{
		IKEProposals: []string{"sunrise_legacy_android"},
	}

	props, profiles, effective, err := buildIKEProposals(cfg, nil, 0)
	if err != nil {
		t.Fatalf("buildIKEProposals failed: %v", err)
	}
	if len(props) == 0 {
		t.Fatalf("expected non-empty proposals")
	}
	if len(profiles) == 0 {
		t.Fatalf("expected offered profile summaries")
	}
	if len(effective) == 0 {
		t.Fatalf("expected effective alg set summary")
	}

	for _, p := range props {
		for _, tr := range p.Transforms {
			if tr.Type != ikev2.TransformTypeEncr {
				continue
			}
			if tr.ID == ikev2.ENCR_DES || tr.ID == ikev2.ENCR_3DES {
				t.Fatalf("unexpected legacy encryption in disabled mode: %v", tr.ID)
			}
		}
	}
}

func TestBuildIKEProposalsSunriseLegacyEnabled(t *testing.T) {
	cfg := &Config{
		IKEProposals:         []string{"sunrise_legacy_android"},
		EnableLegacyCiphers:  true,
		AllowedLegacyCiphers: []string{"3des", "des"},
	}

	props, _, _, err := buildIKEProposals(cfg, nil, 0)
	if err != nil {
		t.Fatalf("buildIKEProposals failed: %v", err)
	}

	foundDES := false
	found3DES := false
	for _, p := range props {
		for _, tr := range p.Transforms {
			if tr.Type != ikev2.TransformTypeEncr {
				continue
			}
			if tr.ID == ikev2.ENCR_DES {
				foundDES = true
			}
			if tr.ID == ikev2.ENCR_3DES {
				found3DES = true
			}
		}
	}
	if !foundDES || !found3DES {
		t.Fatalf("expected both DES and 3DES in enabled mode: des=%v 3des=%v", foundDES, found3DES)
	}
}

func TestBuildIKEProposalsAllOfferedEncrCreatable(t *testing.T) {
	cfg := &Config{
		IKEProposals: []string{
			"aes128-sha256-modp2048",
			"aes256gcm16-prfsha256-modp2048",
		},
	}
	props, _, _, err := buildIKEProposals(cfg, nil, 0)
	if err != nil {
		t.Fatalf("buildIKEProposals failed: %v", err)
	}
	for _, p := range props {
		for _, tr := range p.Transforms {
			if tr.Type != ikev2.TransformTypeEncr {
				continue
			}
			keyBits := 0
			for _, attr := range tr.Attributes {
				if attr.Type == ikev2.AttributeKeyLength {
					keyBits = int(attr.Val)
					break
				}
			}
			if _, err := crypto.GetEncrypterWithKeyLen(uint16(tr.ID), keyBits); err != nil {
				t.Fatalf("offered algorithm not creatable, id=%d keyBits=%d err=%v", tr.ID, keyBits, err)
			}
		}
	}
}

func TestBuildIKEProposalsProfileOffset(t *testing.T) {
	cfg := &Config{
		IKEProposals: []string{
			"aes128-sha1-modp1024",
			"aes128-sha256-modp2048",
		},
	}
	props0, profiles0, _, err := buildIKEProposals(cfg, nil, 0)
	if err != nil {
		t.Fatalf("buildIKEProposals offset=0 failed: %v", err)
	}
	props1, profiles1, _, err := buildIKEProposals(cfg, nil, 1)
	if err != nil {
		t.Fatalf("buildIKEProposals offset=1 failed: %v", err)
	}
	if len(props0) == 0 || len(props1) == 0 {
		t.Fatalf("expected non-empty proposal lists")
	}
	if profiles0[0] == profiles1[0] {
		t.Fatalf("expected profile[0] to change after offset")
	}
}
