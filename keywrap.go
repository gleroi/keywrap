// Package keywrap provides a set of algorithms to wrap/unwrap keywrap with an encryption key.
//
// Currently, the following algorithms are implemented:
//  - RFC3394: AES Key Wrap Algorithm
package keywrap

// KeyWrapper defines the methods to wrap and unwrap a key with an encryption key
// whatever is the underlying algorithm
type KeyWrapper interface {
	Wrap(kek []byte, text []byte) ([]byte, error)
	Unwrap(kek []byte, cypheredText []byte) ([]byte, error)
}
