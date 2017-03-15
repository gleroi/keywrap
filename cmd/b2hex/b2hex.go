package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var encode = flag.Bool("e", false, "encode hex to base64")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [options] <data>\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "\t convert base64 to hex\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "no data to process\n")
		flag.Usage()
		return
	}

	var inputs = flag.Args()
	if *encode {
		for _, input := range inputs {
			data, err := hex.DecodeString(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not decode hex value: %s", input)
				continue
			}
			fmt.Fprintln(os.Stdout, base64.StdEncoding.EncodeToString(data))
		}
	} else {
		for _, input := range inputs {
			data, err := base64.StdEncoding.DecodeString(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not decode base64 value: %s", input)
				continue
			}
			fmt.Fprintln(os.Stdout, strings.ToUpper(hex.EncodeToString(data)))
		}
	}
}
