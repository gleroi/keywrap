// Package rfc3394 provides the AES Key Wrap algorithm as described in RFC3394
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
	if len(text) < minTextSize+1 {
		return nil, errors.New("text is too small, expecting at least 9 bytes")
	}
	if (len(text))%blockSize != 0 {
		return nil, errors.New("text length must be a multiple of 8")
	}
	if len(key) < minKeySize {
		return nil, errors.New("key is too small, expecting at least 128 bits")
	}
	var cypher, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var n = len(text)/blockSize - 1
	var A = make([]byte, blockSize)
	copy(A, text[0:blockSize])
	var R = make([]byte, n*blockSize)
	copy(R, text[blockSize:])

	var t = make([]byte, blockSize)
	var ARi = make([]byte, blockSize*2)
	var B = make([]byte, blockSize*2)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			byteArray(t, uint64(n*j+i+1))
			for k := 0; k < blockSize; k++ {
				ARi[k] = A[k] ^ t[k]
			}
			var Ri = R[i*blockSize : (i+1)*blockSize]
			copy(ARi[blockSize:], Ri)
			cypher.Decrypt(B, ARi)
			copy(A, B[0:blockSize])
			copy(Ri, B[blockSize:])
		}
	}
	return R, nil
}
