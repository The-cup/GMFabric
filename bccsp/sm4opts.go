package bccsp

import "io"

type SM4CBCPKCS7ModeOpts struct {
	IV []byte
	PRNG io.Reader
}