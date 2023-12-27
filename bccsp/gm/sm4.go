/*
Copyright 2023 kasdect@163.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gm

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm4"
	"io"
	"strconv"
)

func GetRandomBytes(len int) ([]byte, error) {
	if len < 0 {
		return nil, errors.New("Len must be larger than 0")
	}

	buffer := make([]byte, len)

	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
	}

	return buffer, nil
}

func Sm4CbcEncrypt(key []byte, in []byte, iv []byte) (out []byte, err error) {
	if len(key) != sm4.BlockSize {
		return nil, errors.New("SM4: invalid key size " + strconv.Itoa(len(key)))
	}

	if len(iv) != sm4.BlockSize {
		return nil, errors.New("SM4: invalid iv size " + strconv.Itoa(len(key)))
	}

	inData := in
	out = make([]byte, len(inData))
	c, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(inData)/16; i++ {
		in_tmp := xor(inData[i*16:i*16+16], iv)
		out_tmp := make([]byte, 16)
		c.Encrypt(out_tmp, in_tmp)
		copy(out[i*16:i*16+16], out_tmp)
		iv = out_tmp
	}

	return out, nil
}

func Sm4CbcDecrypt(key []byte, in []byte, iv []byte) (out []byte, err error) {
	if len(key) != sm4.BlockSize {
		return nil, errors.New("SM4: invalid key size " + strconv.Itoa(len(key)))
	}

	if len(iv) != sm4.BlockSize {
		return nil, errors.New("SM4: invalid iv size " + strconv.Itoa(len(key)))
	}

	inData := in
	out = make([]byte, len(inData))
	c, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(inData)/16; i++ {
		in_tmp := inData[i*16 : i*16+16]
		out_tmp := make([]byte, 16)
		c.Decrypt(out_tmp, in_tmp)
		out_tmp = xor(out_tmp, iv)
		copy(out[i*16:i*16+16], out_tmp)
		iv = in_tmp
	}

	return out, nil
}

func xor(in, iv []byte) (out []byte) {
	if len(in) != len(iv) {
		return nil
	}

	out = make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		out[i] = in[i] ^ iv[i]
	}
	return
}

func pkcs7Padding(src []byte) []byte {
	padding := sm4.BlockSize - len(src)%sm4.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	if unpadding > sm4.BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

func sm4CBCEncrypt(key, s []byte) ([]byte, error) {
	return sm4CBCEncryptWithRand(rand.Reader, key, s)
}

func sm4CBCEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	if len(s)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	ciphertext := make([]byte, sm4.BlockSize+len(s))
	iv := ciphertext[:sm4.BlockSize]
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}

	srcText, err := Sm4CbcEncrypt(key, s, iv)
	if err != nil {
		return nil, err
	}

	copy(ciphertext[sm4.BlockSize:], srcText)

	return ciphertext, nil
}

func sm4CBCEncryptWithIV(IV []byte, key, s []byte) ([]byte, error) {
	if len(s)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}
	if len(IV) != sm4.BlockSize {
		return nil, errors.New("Invalid IV. It must have length the block size")
	}

	ciphertext := make([]byte, sm4.BlockSize+len(s))
	copy(ciphertext[:sm4.BlockSize], IV)

	srcText, err := Sm4CbcEncrypt(key, s, IV)
	if err != nil {
		return nil, err
	}

	copy(ciphertext[sm4.BlockSize:], srcText)

	return ciphertext, nil
}

func sm4CBCDecrypt(key, src []byte) ([]byte, error) {
	if len(src) < sm4.BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}
	iv := src[:sm4.BlockSize]
	src = src[sm4.BlockSize:]

	if len(src)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	src, err := Sm4CbcDecrypt(key, src, iv)
	if err != nil {
		return nil, err
	}
	return src, nil
}

func SM4CBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	tmp := pkcs7Padding(src)

	return sm4CBCEncrypt(key, tmp)
}

func SM4CBCPKCS7EncryptWithRand(prng io.Reader, key, src []byte) ([]byte, error) {
	tmp := pkcs7Padding(src)

	return sm4CBCEncryptWithRand(prng, key, tmp)
}

func SM4CBCPKCS7EncryptWithIV(IV []byte, key, src []byte) ([]byte, error) {
	tmp := pkcs7Padding(src)

	return sm4CBCEncryptWithIV(IV, key, tmp)
}

func SM4CBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	pt, err := sm4CBCDecrypt(key, src)
	if err == nil {
		return pkcs7UnPadding(pt)
	}
	return nil, err
}

type sm4cbcpkcs7Encryptor struct{}

func (e *sm4cbcpkcs7Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	switch o := opts.(type) {
	case *bccsp.SM4CBCPKCS7ModeOpts:
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			return SM4CBCPKCS7EncryptWithIV(o.IV, k.(*sm4PrivateKey).privKey, plaintext)
		} else if o.PRNG != nil {
			return SM4CBCPKCS7EncryptWithRand(o.PRNG, k.(*sm4PrivateKey).privKey, plaintext)
		}
		return SM4CBCPKCS7Encrypt(k.(*sm4PrivateKey).privKey, plaintext)
	case bccsp.SM4CBCPKCS7ModeOpts:
		return e.Encrypt(k, plaintext, &o)
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}

type sm4cbcpkcs7Decryptor struct{}

func (*sm4cbcpkcs7Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	switch opts.(type) {
	case *bccsp.SM4CBCPKCS7ModeOpts, bccsp.SM4CBCPKCS7ModeOpts:
		return SM4CBCPKCS7Decrypt(k.(*sm4PrivateKey).privKey, ciphertext)
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}
