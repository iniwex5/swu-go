package crypto

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

// PRF (伪随机函数) 接口
type PRF interface {
	Compute(key, data []byte) []byte
	KeyLen() int
}

type hmacPRF struct {
	compute func(key, data []byte) []byte
	keyLen  int
}

func (h *hmacPRF) Compute(key, data []byte) []byte {
	return h.compute(key, data)
}

func (h *hmacPRF) KeyLen() int {
	return h.keyLen
}

type xcbcPRF struct{}

func (x *xcbcPRF) Compute(key, data []byte) []byte {
	return aesXCBCPRF128(key, data)
}

func (x *xcbcPRF) KeyLen() int {
	return 16
}

var (
	PRF_HMAC_MD5      = &hmacPRF{compute: func(key, data []byte) []byte { return computeHMAC(md5.New, key, data) }, keyLen: 16}
	PRF_HMAC_SHA1     = &hmacPRF{compute: func(key, data []byte) []byte { return computeHMAC(sha1.New, key, data) }, keyLen: 20}
	PRF_HMAC_SHA2_256 = &hmacPRF{compute: func(key, data []byte) []byte { return computeHMAC(sha256.New, key, data) }, keyLen: 32}
	PRF_HMAC_SHA2_384 = &hmacPRF{compute: func(key, data []byte) []byte { return computeHMAC(sha512.New384, key, data) }, keyLen: 48}
	PRF_HMAC_SHA2_512 = &hmacPRF{compute: func(key, data []byte) []byte { return computeHMAC(sha512.New, key, data) }, keyLen: 64}
	PRF_AES128_XCBC   = &xcbcPRF{}
)

// RFC 7296 2.13 节. 生成密钥材料
// prf+ (K,S) = T1 | T2 | T3 | T4 | ...
// T1 = prf (K, S | 0x01)
// T2 = prf (K, T1 | S | 0x02)
// T3 = prf (K, T2 | S | 0x03)
func PrfPlus(prf PRF, key []byte, seed []byte, totalBytes int) ([]byte, error) {
	var result []byte
	var lastBlock []byte
	blockIndex := 1

	for len(result) < totalBytes {
		input := make([]byte, 0, len(lastBlock)+len(seed)+1)
		if blockIndex > 1 {
			input = append(input, lastBlock...)
		}
		input = append(input, seed...)
		input = append(input, byte(blockIndex))
		lastBlock = prf.Compute(key, input)
		result = append(result, lastBlock...)
		blockIndex++

		if blockIndex > 255 {
			return nil, errors.New("PRF+ 溢出: 块太多")
		}
	}

	return result[:totalBytes], nil
}

func GetPRF(id uint16) (PRF, error) {
	// 载荷定义中的 ID
	switch id {
	case 1:
		return PRF_HMAC_MD5, nil
	case 2:
		return PRF_HMAC_SHA1, nil
	case 4:
		return PRF_AES128_XCBC, nil
	case 5:
		return PRF_HMAC_SHA2_256, nil
	case 6:
		return PRF_HMAC_SHA2_384, nil
	case 7:
		return PRF_HMAC_SHA2_512, nil
	default:
		return nil, errors.New("不支持的 PRF ID")
	}
}

func computeHMAC(newHash func() hash.Hash, key, data []byte) []byte {
	h := hmac.New(newHash, key)
	h.Write(data)
	return h.Sum(nil)
}

func aesXCBCPRF128(key, data []byte) []byte {
	normKey := normalizeXCBCPRFKey(key)
	return aesXCBCMAC(normKey, data)
}

func normalizeXCBCPRFKey(key []byte) []byte {
	switch {
	case len(key) == 16:
		return append([]byte(nil), key...)
	case len(key) < 16:
		k := make([]byte, 16)
		copy(k, key)
		return k
	default:
		zeroKey := make([]byte, 16)
		return aesXCBCMAC(zeroKey, key)
	}
}

func aesXCBCMAC(key, data []byte) []byte {
	if len(key) != 16 {
		panic("AES-XCBC requires 16-byte key")
	}
	baseCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	k1 := make([]byte, 16)
	k2 := make([]byte, 16)
	k3 := make([]byte, 16)
	c1 := bytesRepeat(0x01, 16)
	c2 := bytesRepeat(0x02, 16)
	c3 := bytesRepeat(0x03, 16)
	baseCipher.Encrypt(k1, c1)
	baseCipher.Encrypt(k2, c2)
	baseCipher.Encrypt(k3, c3)

	workCipher, err := aes.NewCipher(k1)
	if err != nil {
		panic(err)
	}

	e := make([]byte, 16)
	if len(data) == 0 {
		last := make([]byte, 16)
		last[0] = 0x80
		xorBlock(last, k3)
		workCipher.Encrypt(e, last)
		return e
	}

	blocks := (len(data) + 15) / 16
	for i := 0; i < blocks-1; i++ {
		block := make([]byte, 16)
		copy(block, data[i*16:(i+1)*16])
		xorBlock(block, e)
		workCipher.Encrypt(e, block)
	}

	last := make([]byte, 16)
	remain := data[(blocks-1)*16:]
	copy(last, remain)
	if len(remain) == 16 {
		xorBlock(last, e)
		xorBlock(last, k2)
	} else {
		last[len(remain)] = 0x80
		xorBlock(last, e)
		xorBlock(last, k3)
	}
	workCipher.Encrypt(e, last)
	return e
}

func xorBlock(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
