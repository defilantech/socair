package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// maxRequest bounds the request read from stdin.
const maxRequest = 128 << 20

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func main() {
	in, err := io.ReadAll(io.LimitReader(os.Stdin, maxRequest+1))
	if err == nil && len(in) > maxRequest {
		err = fmt.Errorf("request over %d bytes", maxRequest)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "socair-sigstore:", err)
		os.Exit(2)
	}
	out, err := handle(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Stdout.Write(append(out, '\n'))
}
