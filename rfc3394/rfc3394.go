package rfc3394

import (
	"crypto/aes"
	"errors"
	"keywrap"
)

type rfc3394Wrapper struct {
}

// NewWrapper creates a key wrapper/unwrapper implementing RFC3394
func NewWrapper() keywrap.KeyWrapper {
	return rfc3394Wrapper{}
}

const blockSize = 8
const minTextSize = blockSize * 2
const minKeySize = 128 / 8

func byteArray(dst []byte, t uint64) {
	var max = len(dst)
	for i := 0; i < max; i++ {
		dst[max-i-1] = byte(t & 0xFF)
		t = t >> 8
	}
}

func (w rfc3394Wrapper) Wrap(key []byte, text []byte) ([]byte, error) {
	if len(text) < minTextSize {
		return nil, errors.New("text is too small, expecting at least 8 bytes")
	}
	if len(text)%blockSize != 0 {
		return nil, errors.New("text length must be a multiple of 8")
	}
	if len(key) < minKeySize {
		return nil, errors.New("key is too small, expecting at least 128 bits")
	}
	var cypher, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var n = uint64(len(text)) / blockSize
	var R = make([]byte, n*blockSize)
	var C = make([]byte, (n+1)*blockSize)
	var A = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	copy(R, text)

	var t = make([]byte, blockSize)
	var ARi = make([]byte, blockSize*2)
	var B = make([]byte, blockSize*2)
	for j := uint64(0); j < 6; j++ {
		for i := uint64(0); i < n; i++ {
			var Ri = R[i*blockSize : (i+1)*blockSize]
			copy(ARi, A)
			copy(ARi[blockSize:], Ri)
			cypher.Encrypt(B, ARi)
			byteArray(t, n*j+i+1)
			for k := 0; k < blockSize; k++ {
				A[k] = B[k] ^ t[k]
				Ri[k] = B[blockSize+k]
			}
		}
	}
	copy(C, A)
	copy(C[blockSize:], R)

	return C, nil
}

func (w rfc3394Wrapper) Unwrap(key []byte, text []byte) ([]byte, error) {
	return nil, errors.New("Not implemented")
}
