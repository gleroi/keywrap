package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gleroi/keywrap/rfc3394"
)

type codec interface {
	DecodeString(input string) []byte
	EncodeToString(input []byte) string
}

type hexCodec struct{}

func (decoder hexCodec) DecodeString(input string) []byte {
	output, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	return output
}

func (decoder hexCodec) EncodeToString(input []byte) string {
	return strings.ToUpper(hex.EncodeToString(input))
}

type base64Codec struct{}

func (decoder base64Codec) DecodeString(input string) []byte {
	output, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		panic(err)
	}
	return output
}

func (decoder base64Codec) EncodeToString(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

func main() {
	flag.Usage = func() {
		var programName = filepath.Base(os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage : %s [options] <hex-kek> <keys...>\n", programName)
		flag.PrintDefaults()
	}
	var b64 = flag.Bool("b64", false, "input/output values are base-64 encoded")
	flag.Parse()

	if flag.NArg() < 2 {
		fmt.Fprintf(os.Stderr, "expecting at least to values, a key encryption key (kek) and a key\n")
		flag.Usage()
		return
	}

	var args = flag.Args()
	var kekString = args[0]
	var inputs = args[1:]
	var encoder codec = hexCodec{}
	if *b64 {
		encoder = base64Codec{}
	}
	var wrapper = rfc3394.NewWrapper()
	kek, err := hex.DecodeString(kekString)
	if err != nil {
		panic(err)
	}

	for _, input := range inputs {
		var key = encoder.DecodeString(input)
		cryptedKey, err := wrapper.Wrap(kek, key)
		if err != nil {
			fmt.Println("Could not encrypt key ", input, ": ", err)
		}
		fmt.Println(encoder.EncodeToString(cryptedKey))
	}
}
