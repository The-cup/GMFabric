/*
Copyright 2023 kasdect@163.com

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"io"
	"math/big"
	mrand "math/rand"
	"testing"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm4"
)

func TestCBCPKCS7EncryptCBCPKCS7Decrypt(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	rand.Reader.Read(key)
	var ptext = []byte("a message with arbitrary length (42 bytes)")

	encrypted, encErr := SM4CBCPKCS7Encrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, encErr)
	}

	decrypted, dErr := SM4CBCPKCS7Decrypt(key, encrypted)
	if dErr != nil {
		t.Fatalf("Error decrypting the encrypted '%s': %v", ptext, dErr)
	}

	if string(ptext[:]) != string(decrypted[:]) {
		t.Fatal("Decrypt( Encrypt( ptext ) ) != ptext: Ciphertext decryption with the same key must result in the original plaintext!")
	}
}

func TestCBCPKCS7Encrypt_EmptyPlaintext(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	rand.Reader.Read(key)

	t.Log("Generated key: ", key)

	var emptyPlaintext = []byte("")
	t.Log("Plaintext length: ", len(emptyPlaintext))

	ciphertext, encErr := SM4CBCPKCS7Encrypt(key, emptyPlaintext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%v'", encErr)
	}

	// Expected ciphertext length: 32 (=32)
	// As part of the padding, at least one block gets encrypted (while the first block is the IV)
	const expectedLength = sm4.BlockSize
	if len(ciphertext) != expectedLength {
		t.Fatalf("Wrong ciphertext length. Expected %d, received %d", expectedLength, len(ciphertext))
	}

	t.Log("Ciphertext length: ", len(ciphertext))
	t.Log("Cipher: ", ciphertext)
}

func TestCBCPKCS7Encrypt_VerifyRandomIVs(t *testing.T) {
	t.Parallel()

	key := make([]byte, aes.BlockSize)
	rand.Reader.Read(key)
	t.Log("Key 1", key)

	var ptext = []byte("a message to encrypt")

	_, err := SM4CBCPKCS7Encrypt(key, ptext)
	if err != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, err)
	}

	iv1 := sm4.IV

	// Expecting a different IV if same message is encrypted with same key
	_, err = SM4CBCPKCS7Encrypt(key, ptext)
	if err != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, err)
	}

	iv2 := sm4.IV

	t.Log("Ciphertext1: ", iv1)
	t.Log("Ciphertext2: ", iv2)
	t.Log("bytes.Equal: ", bytes.Equal(iv1, iv2))

	if bytes.Equal(iv1, iv2) {
		t.Fatal("Error: ciphertexts contain identical initialization vectors (IVs)")
	}
}

func TestCBCPKCS7Encrypt_CorrectCiphertextLengthCheck(t *testing.T) {
	t.Parallel()

	key := make([]byte, aes.BlockSize)
	rand.Reader.Read(key)

	var ptext = []byte("0123456789ABCDEF")

	for i := 1; i < aes.BlockSize; i++ {
		ciphertext, err := SM4CBCPKCS7Encrypt(key, ptext[:i])
		if err != nil {
			t.Fatal("Error encrypting '", ptext, "'")
		}

		expectedLength := aes.BlockSize
		if len(ciphertext) != expectedLength {
			t.Fatalf("Incorrect ciphertext incorrect: expected '%d', received '%d'", expectedLength, len(ciphertext))
		}
	}
}

func TestSM4RelatedUtilFunctions(t *testing.T) {
	t.Parallel()

	key, err := GetRandomBytes(16)
	if err != nil {
		t.Fatalf("Failed generating AES key [%s]", err)
	}

	for i := 1; i < 100; i++ {
		l, err := rand.Int(rand.Reader, big.NewInt(1024))
		if err != nil {
			t.Fatalf("Failed generating AES key [%s]", err)
		}
		msg, err := GetRandomBytes(int(l.Int64()) + 1)
		if err != nil {
			t.Fatalf("Failed generating AES key [%s]", err)
		}

		ct, err := SM4CBCPKCS7Encrypt(key, msg)
		if err != nil {
			t.Fatalf("Failed encrypting [%s]", err)
		}

		msg2, err := SM4CBCPKCS7Decrypt(key, ct)
		if err != nil {
			t.Fatalf("Failed decrypting [%s]", err)
		}

		if !bytes.Equal(msg, msg2) {
			t.Fatalf("Wrong decryption output [%x][%x]", msg, msg2)
		}
	}
}

func TestVariousSM4KeyEncoding(t *testing.T) {
	t.Parallel()

	key, err := GetRandomBytes(32)
	if err != nil {
		t.Fatalf("Failed generating AES key [%s]", err)
	}

	// PEM format
	pem, err := sm4.WriteKeyToPem(key, nil)
	keyFromPEM, err := sm4.ReadKeyFromPem(pem, nil)
	if err != nil {
		t.Fatalf("Failed converting PEM to AES key [%s]", err)
	}
	if !bytes.Equal(key, keyFromPEM) {
		t.Fatalf("Failed converting PEM to AES key. Keys are different [%x][%x]", key, keyFromPEM)
	}

	// Encrypted PEM format
	pem, err = sm4.WriteKeyToPem(key, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting AES key to Encrypted PEM [%s]", err)
	}
	keyFromPEM, err = sm4.ReadKeyFromPem(pem, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting encrypted PEM to AES key [%s]", err)
	}
	if !bytes.Equal(key, keyFromPEM) {
		t.Fatalf("Failed converting encrypted PEM to AES key. Keys are different [%x][%x]", key, keyFromPEM)
	}
}

func TestAESCBCPKCS7EncryptorDecrypt(t *testing.T) {
	t.Parallel()

	raw, err := GetRandomBytes(16)
	assert.NoError(t, err)

	k := &sm4PrivateKey{privKey: raw, exportable: false}

	msg := []byte("Hello World")
	encryptor := &sm4cbcpkcs7Encryptor{}

	_, err = encryptor.Encrypt(k, msg, nil)
	assert.Error(t, err)

	_, err = encryptor.Encrypt(k, msg, &mocks.EncrypterOpts{})
	assert.Error(t, err)

	_, err = encryptor.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{IV: []byte{1}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid IV. It must have length the block size")

	_, err = encryptor.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{IV: []byte{1}, PRNG: rand.Reader})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid options. Either IV or PRNG should be different from nil, or both nil.")

	_, err = encryptor.Encrypt(k, msg, bccsp.SM4CBCPKCS7ModeOpts{})
	assert.NoError(t, err)

	ct, err := encryptor.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{})
	assert.NoError(t, err)

	decryptor := &sm4cbcpkcs7Decryptor{}

	_, err = decryptor.Decrypt(k, ct, nil)
	assert.Error(t, err)

	_, err = decryptor.Decrypt(k, ct, &mocks.EncrypterOpts{})
	assert.Error(t, err)

	msg2, err := decryptor.Decrypt(k, ct, &bccsp.SM4CBCPKCS7ModeOpts{})
	assert.NoError(t, err)
	assert.Equal(t, msg, msg2)
}

func TestAESCBCPKCS7EncryptorWithIVSameCiphertext(t *testing.T) {
	t.Parallel()

	raw, err := GetRandomBytes(16)
	assert.NoError(t, err)

	k := &sm4PrivateKey{privKey: raw, exportable: false}

	msg := []byte("Hello World")
	encryptor := &sm4cbcpkcs7Encryptor{}

	iv := make([]byte, sm4.BlockSize)

	ct, err := encryptor.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{IV: iv})
	assert.NoError(t, err)
	assert.NotNil(t, ct)
	assert.Equal(t, iv, sm4.IV)

	ct2, err := encryptor.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{IV: iv})
	assert.NoError(t, err)
	assert.NotNil(t, ct2)
	assert.Equal(t, iv, sm4.IV)

	assert.Equal(t, ct, ct2)
}

func TestAESCBCPKCS7EncryptorWithRandSameCiphertext(t *testing.T) {
	t.Parallel()

	raw, err := GetRandomBytes(16)
	assert.NoError(t, err)

	k := &sm4PrivateKey{privKey: raw, exportable: false}

	msg := []byte("Hello World")
	encryptor := &sm4cbcpkcs7Encryptor{}

	r := mrand.New(mrand.NewSource(0))
	iv := make([]byte, sm4.BlockSize)
	_, err = io.ReadFull(r, iv)
	assert.NoError(t, err)

	r = mrand.New(mrand.NewSource(0))
	ct, err := encryptor.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{PRNG: r})
	assert.NoError(t, err)
	assert.NotNil(t, ct)
	assert.Equal(t, iv, sm4.IV)

	r = mrand.New(mrand.NewSource(0))
	ct2, err := encryptor.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{PRNG: r})
	assert.NoError(t, err)
	assert.NotNil(t, ct2)
	assert.Equal(t, iv, sm4.IV)

	assert.Equal(t, ct, ct2)
}
