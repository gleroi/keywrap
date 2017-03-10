package keywrap_test

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/gleroi/keywrap/rfc3394"
)

func Example_wrap() {
	var wrapper = rfc3394.NewWrapper()
	kek, err := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	key, err := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	wrappedKey, err := wrapper.Wrap(kek, key)
	if err != nil {
		panic(err)
	}
	var hexWrappedKey = strings.ToUpper(hex.EncodeToString(wrappedKey))
	fmt.Println(hexWrappedKey)
	// Output: 1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5
}

func Example_unwrap() {
	var wrapper = rfc3394.NewWrapper()
	kek, err := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	wrappedKey, err := hex.DecodeString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
	key, err := wrapper.Unwrap(kek, wrappedKey)
	if err != nil {
		panic(err)
	}
	var hexKey = strings.ToUpper(hex.EncodeToString(key))
	fmt.Println(hexKey)
	// Output: 00112233445566778899AABBCCDDEEFF
}
