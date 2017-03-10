package rfc3394_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gleroi/keywrap"
	"github.com/gleroi/keywrap/rfc3394"
)

func testWrap(t *testing.T, skek, skey, sexpected string) {
	var wrapper keywrap.KeyWrapper
	wrapper = rfc3394.NewWrapper()
	kek, err := hex.DecodeString(skek)
	key, err := hex.DecodeString(skey)
	if err != nil {
		panic("could not read test input")
	}
	cypher, err := wrapper.Wrap(kek, key)
	if err != nil {
		t.Error(err)
		return
	}
	cypherHex := hex.EncodeToString(cypher)
	if cypherHex != sexpected {
		t.Error("Expected: ", sexpected, " actual: ", cypherHex)
	}
}

func testUnwrap(t *testing.T, skek, sexpectedKey, sencryptedKey string) {
	var wrapper keywrap.KeyWrapper
	wrapper = rfc3394.NewWrapper()
	kek, err := hex.DecodeString(skek)
	key, err := hex.DecodeString(sencryptedKey)
	if err != nil {
		panic("could not read test input")
	}
	uncypher, err := wrapper.Unwrap(kek, key)
	if err != nil {
		t.Error(err)
		return
	}
	uncypherHex := strings.ToUpper(hex.EncodeToString(uncypher))
	if uncypherHex != sexpectedKey {
		t.Error("Expected: ", sexpectedKey, " actual: ", uncypherHex)
	}
}

/*
Test Wrap function
*/

func TestRfcWrap128BitsWith128BitsKekMustWork_1(t *testing.T) {
	testWrap(t, "000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF",
		"1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
}

func TestRfcWrap128BitsWith128BitsKekMustWork_2(t *testing.T) {
	testWrap(t, "3BEB4FFCA96E8869FA1F6E4BD78AB1D5", "000102030405060708090A0B0C0D0E0F",
		"580aebdc1265a65bb461062ccf2b181541340899fec45166")
}

func TestRfcWrap128BitsWith128BitsKekMustWork_3(t *testing.T) {
	testWrap(t, "3BEB4FFCA96E8869FA1F6E4BD78AB1D5", "00C1960B527DBEA113DC3779707CC394",
		"a1e32721b8fce2d6287c77380440b120ed2b3bb1a9ca3440")
}

func TestRfcWrap128BitsWith192BitsKekMustWork(t *testing.T) {
	testWrap(t, "000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF",
		"96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d")
}

func TestRfcWrap128BitsWith256BitsKekMustWork(t *testing.T) {
	testWrap(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF",
		"64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7")
}

func TestRfcWrap192BitsWith192BitsKekMustWork(t *testing.T) {
	testWrap(t, "000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607",
		"031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2")
}

func TestRfcWrap192BitsWith256BitsKekMustWork(t *testing.T) {
	testWrap(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607",
		"a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1")
}

func TestRfcWrap256BitsWith256BitsKekMustWork(t *testing.T) {
	testWrap(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
		"28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21")
}

/*
Test Unwrap function
*/

func TestRfcUnwrap128BitsWith128BitsKekMustWork_1(t *testing.T) {
	testUnwrap(t, "000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF",
		"1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
}

func TestRfcUnwrap128BitsWith128BitsKekMustWork_2(t *testing.T) {
	testUnwrap(t, "3BEB4FFCA96E8869FA1F6E4BD78AB1D5", "000102030405060708090A0B0C0D0E0F",
		"580aebdc1265a65bb461062ccf2b181541340899fec45166")
}

func TestRfcUnwrap128BitsWith128BitsKekMustWork_3(t *testing.T) {
	testUnwrap(t, "3BEB4FFCA96E8869FA1F6E4BD78AB1D5", "00C1960B527DBEA113DC3779707CC394",
		"a1e32721b8fce2d6287c77380440b120ed2b3bb1a9ca3440")
}

func TestRfcUnwrap128BitsWith192BitsKekMustWork(t *testing.T) {
	testUnwrap(t, "000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF",
		"96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d")
}

func TestRfcUnwrap128BitsWith256BitsKekMustWork(t *testing.T) {
	testUnwrap(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF",
		"64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7")
}

func TestRfcUnwrap192BitsWith192BitsKekMustWork(t *testing.T) {
	testUnwrap(t, "000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607",
		"031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2")
}

func TestRfcUnwrap192BitsWith256BitsKekMustWork(t *testing.T) {
	testUnwrap(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607",
		"a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1")
}

func TestRfcUnwrap256BitsWith256BitsKekMustWork(t *testing.T) {
	testUnwrap(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
		"28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21")
}
