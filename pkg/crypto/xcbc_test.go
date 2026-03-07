package crypto

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}
	return b
}

func TestAESXCBCMAC_RFC3566_Vector4(t *testing.T) {
	key := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	msg := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	want := mustHex(t, "F54F0EC8D2B9F3D36807734BD5283FD4")

	got := aesXCBCMAC(key, msg)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("AES-XCBC-MAC mismatch: got %x want %x", got, want)
	}
}

func TestAESXCBCMAC_RFC3566_Vectors(t *testing.T) {
	key := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	cases := []struct {
		msg  string
		want string
	}{
		{"", "75F0251D528AC01C4573DFD584D79F29"},
		{"000102", "5B376580AE2F19AFE7219CEEF172756F"},
		{"000102030405060708090A0B0C0D0E0F", "D2A246FA349B68A79998A4394FF7A263"},
		{"000102030405060708090A0B0C0D0E0F10111213", "47F51B4564966215B8985C63055ED308"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "F54F0EC8D2B9F3D36807734BD5283FD4"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021", "BECBB3BCCDB518A30677D5481FB6B4D8"},
	}
	for _, tc := range cases {
		got := aesXCBCMAC(key, mustHex(t, tc.msg))
		want := mustHex(t, tc.want)
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Fatalf("AES-XCBC-MAC mismatch for msg=%s: got %x want %x", tc.msg, got, want)
		}
	}
}

func TestAESXCBCPRF_Basic(t *testing.T) {
	key := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	msg := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	got := aesXCBCPRF128(key, msg)
	if len(got) != 16 {
		t.Fatalf("AES-XCBC-PRF output size mismatch: got %d want 16", len(got))
	}
	got2 := aesXCBCPRF128(key, msg)
	if hex.EncodeToString(got) != hex.EncodeToString(got2) {
		t.Fatalf("AES-XCBC-PRF is not deterministic: %x vs %x", got, got2)
	}
}

func TestAESXCBCPRF_RFC4434_Vectors(t *testing.T) {
	cases := []struct {
		key  string
		msg  string
		want string
	}{
		{
			key:  "000102030405060708090A0B0C0D0E0F",
			msg:  "000102030405060708090A0B0C0D0E0F10111213",
			want: "47F51B4564966215B8985C63055ED308",
		},
		{
			key:  "00010203040506070809",
			msg:  "000102030405060708090A0B0C0D0E0F10111213",
			want: "0FA087AF7D866E7653434E602FDDE835",
		},
		{
			key:  "000102030405060708090A0B0C0D0E0FEDCB",
			msg:  "000102030405060708090A0B0C0D0E0F10111213",
			want: "8CD3C93AE598A9803006FFB67C40E9E4",
		},
	}
	for _, tc := range cases {
		got := aesXCBCPRF128(mustHex(t, tc.key), mustHex(t, tc.msg))
		want := mustHex(t, tc.want)
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Fatalf("AES-XCBC-PRF mismatch for key=%s: got %x want %x", tc.key, got, want)
		}
	}
}
