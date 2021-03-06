PACKAGE DOCUMENTATION

package keywrap
    import "keywrap"

    Package keywrap provides a set of algorithms to wrap/unwrap keywrap with
    an encryption key.

    Currently, the following algorithms are implemented:

    - RFC3394: AES Key Wrap Algorithm

    Example:
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


    Example:
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

TYPES

type KeyWrapper interface {
    Wrap(kek []byte, text []byte) ([]byte, error)
    Unwrap(kek []byte, cypheredText []byte) ([]byte, error)
}
    KeyWrapper defines the methods to wrap and unwrap a key with an
    encryption key whatever is the underlying algorithm

SUBDIRECTORIES

	rfc3394

