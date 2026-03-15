package driver

import "testing"

func TestIKEv2AlgToXFRMCryptLegacy(t *testing.T) {
	desInfo, err := IKEv2AlgToXFRMCrypt(2, 0)
	if err != nil {
		t.Fatalf("DES map failed: %v", err)
	}
	if desInfo.Name == "" || desInfo.KeyBits != 64 {
		t.Fatalf("unexpected DES map result: %+v", desInfo)
	}

	des3Info, err := IKEv2AlgToXFRMCrypt(3, 0)
	if err != nil {
		t.Fatalf("3DES map failed: %v", err)
	}
	if des3Info.Name == "" || des3Info.KeyBits != 192 {
		t.Fatalf("unexpected 3DES map result: %+v", des3Info)
	}
}
