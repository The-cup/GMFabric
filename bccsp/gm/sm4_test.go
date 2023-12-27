/*
Copyright 2023 kasdect@163.com

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"bytes"
	"crypto/rand"
	"fmt"
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

func TestPKCS7Padding(t *testing.T) {
	t.Parallel()

	// 0 byte/length ptext
	ptext := []byte("")
	expected := []byte{16, 16, 16, 16,
		16, 16, 16, 16,
		16, 16, 16, 16,
		16, 16, 16, 16}
	result := pkcs7Padding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("Padding error! Expected: ", expected, "', received: '", result, "'")
	}

	// 1 byte/length ptext
	ptext = []byte("1")
	expected = []byte{'1', 15, 15, 15,
		15, 15, 15, 15,
		15, 15, 15, 15,
		15, 15, 15, 15}
	result = pkcs7Padding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("Padding error! Expected: '", expected, "', received: '", result, "'")
	}

	// 2 byte/length ptext
	ptext = []byte("12")
	expected = []byte{'1', '2', 14, 14,
		14, 14, 14, 14,
		14, 14, 14, 14,
		14, 14, 14, 14}
	result = pkcs7Padding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("Padding error! Expected: '", expected, "', received: '", result, "'")
	}

	// 3 to sm4.BlockSize-1 byte plaintext
	ptext = []byte("1234567890ABCDEF")
	for i := 3; i < sm4.BlockSize; i++ {
		result := pkcs7Padding(ptext[:i])

		padding := sm4.BlockSize - i
		expectedPadding := bytes.Repeat([]byte{byte(padding)}, padding)
		expected = append(ptext[:i], expectedPadding...)

		if !bytes.Equal(result, expected) {
			t.Fatal("Padding error! Expected: '", expected, "', received: '", result, "'")
		}
	}

	// sm4.BlockSize length ptext
	ptext = bytes.Repeat([]byte{byte('x')}, sm4.BlockSize)
	result = pkcs7Padding(ptext)

	expectedPadding := bytes.Repeat([]byte{byte(sm4.BlockSize)}, sm4.BlockSize)
	expected = append(ptext, expectedPadding...)

	if len(result) != 2*sm4.BlockSize {
		t.Fatal("Padding error: expected the length of the returned slice to be 2 times sm4.BlockSize")
	}

	if !bytes.Equal(expected, result) {
		t.Fatal("Padding error! Expected: '", expected, "', received: '", result, "'")
	}
}

func TestPKCS7UnPadding(t *testing.T) {
	t.Parallel()

	// 0 byte/length ptext
	expected := []byte("")
	ptext := []byte{16, 16, 16, 16,
		16, 16, 16, 16,
		16, 16, 16, 16,
		16, 16, 16, 16}

	result, _ := pkcs7UnPadding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("UnPadding error! Expected: '", expected, "', received: '", result, "'")
	}

	// 1 byte/length ptext
	expected = []byte("1")
	ptext = []byte{'1', 15, 15, 15,
		15, 15, 15, 15,
		15, 15, 15, 15,
		15, 15, 15, 15}

	result, _ = pkcs7UnPadding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("UnPadding error! Expected: '", expected, "', received: '", result, "'")
	}

	// 2 byte/length ptext
	expected = []byte("12")
	ptext = []byte{'1', '2', 14, 14,
		14, 14, 14, 14,
		14, 14, 14, 14,
		14, 14, 14, 14}

	result, _ = pkcs7UnPadding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("UnPadding error! Expected: '", expected, "', received: '", result, "'")
	}

	// 3 to sm4.BlockSize-1 byte plaintext
	base := []byte("1234567890ABCDEF")
	for i := 3; i < sm4.BlockSize; i++ {
		iPad := sm4.BlockSize - i
		padding := bytes.Repeat([]byte{byte(iPad)}, iPad)
		ptext = append(base[:i], padding...)

		expected := base[:i]
		result, _ := pkcs7UnPadding(ptext)

		if !bytes.Equal(result, expected) {
			t.Fatal("UnPadding error! Expected: '", expected, "', received: '", result, "'")
		}
	}

	// sm4.BlockSize length ptext
	expected = bytes.Repeat([]byte{byte('x')}, sm4.BlockSize)
	padding := bytes.Repeat([]byte{byte(sm4.BlockSize)}, sm4.BlockSize)
	ptext = append(expected, padding...)

	result, _ = pkcs7UnPadding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("UnPadding error! Expected: '", expected, "', received: '", result, "'")
	}
}

func TestCBCEncryptCBCPKCS7Decrypt_BlockSizeLengthPlaintext(t *testing.T) {
	t.Parallel()

	// One of the purposes of this test is to also document and clarify the expected behavior, i.e., that an extra
	// block is appended to the message at the padding stage, as per the spec of PKCS#7 v1.5 [see RFC-2315 p.21]
	key := make([]byte, 16)
	rand.Reader.Read(key)

	//                  1234567890123456
	var ptext = []byte("a 16 byte messag")

	encrypted, encErr := sm4CBCEncrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %v", ptext, encErr)
	}

	decrypted, dErr := SM4CBCPKCS7Decrypt(key, encrypted)
	if dErr == nil {
		t.Fatalf("Expected an error decrypting ptext '%s'. Decrypted to '%v'", dErr, decrypted)
	}
}

func TestCBCPKCS7EncryptCBCDecrypt_ExpectingCorruptMessage(t *testing.T) {
	t.Parallel()

	// One of the purposes of this test is to also document and clarify the expected behavior, i.e., that an extra
	// block is appended to the message at the padding stage, as per the spec of PKCS#7 v1.5 [see RFC-2315 p.21]
	key := make([]byte, 16)
	rand.Reader.Read(key)

	//                  0123456789ABCDEF
	var ptext = []byte("a 16 byte messag")

	encrypted, encErr := SM4CBCPKCS7Encrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting ptext %v", encErr)
	}

	decrypted, dErr := sm4CBCDecrypt(key, encrypted)
	if dErr != nil {
		t.Fatalf("Error encrypting ptext %v, %v", dErr, decrypted)
	}

	if string(ptext[:]) != string(decrypted[:sm4.BlockSize]) {
		t.Log("ptext: ", ptext)
		t.Log("decrypted: ", decrypted[:sm4.BlockSize])
		t.Fatal("Encryption->Decryption with same key should result in original ptext")
	}

	if !bytes.Equal(decrypted[sm4.BlockSize:], bytes.Repeat([]byte{byte(sm4.BlockSize)}, sm4.BlockSize)) {
		t.Fatal("Expected extra block with padding in encrypted ptext", decrypted)
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
	const expectedLength = sm4.BlockSize + sm4.BlockSize
	if len(ciphertext) != expectedLength {
		t.Fatalf("Wrong ciphertext length. Expected %d, received %d", expectedLength, len(ciphertext))
	}

	t.Log("Ciphertext length: ", len(ciphertext))
	t.Log("Cipher: ", ciphertext)
}

func TestCBCEncrypt_EmptyPlaintext(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	rand.Reader.Read(key)
	t.Log("Generated key: ", key)

	var emptyPlaintext = []byte("")
	t.Log("Message length: ", len(emptyPlaintext))

	ciphertext, encErr := sm4CBCEncrypt(key, emptyPlaintext)
	assert.NoError(t, encErr)

	t.Log("Ciphertext length: ", len(ciphertext))

	// Expected cipher length: sm4.BlockSize, the first and only block is the IV
	var expectedLength = sm4.BlockSize

	if len(ciphertext) != expectedLength {
		t.Fatalf("Wrong ciphertext length. Expected: '%d', received: '%d'", expectedLength, len(ciphertext))
	}
	t.Log("Ciphertext: ", ciphertext)
}

func TestCBCPKCS7Encrypt_VerifyRandomIVs(t *testing.T) {
	t.Parallel()

	key := make([]byte, sm4.BlockSize)
	rand.Reader.Read(key)
	t.Log("Key 1", key)

	var ptext = []byte("a message to encrypt")

	cipherText1, err := SM4CBCPKCS7Encrypt(key, ptext)
	if err != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, err)
	}

	// Expecting a different IV if same message is encrypted with same key
	cipherText2, err := SM4CBCPKCS7Encrypt(key, ptext)
	if err != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, err)
	}

	iv1 := cipherText1[:sm4.BlockSize]
	iv2 := cipherText2[:sm4.BlockSize]

	t.Log("Ciphertext1: ", iv1)
	t.Log("Ciphertext2: ", iv2)
	t.Log("bytes.Equal: ", bytes.Equal(iv1, iv2))

	if bytes.Equal(iv1, iv2) {
		t.Fatal("Error: ciphertexts contain identical initialization vectors (IVs)")
	}
}

func TestCBCPKCS7Encrypt_CorrectCiphertextLengthCheck(t *testing.T) {
	t.Parallel()

	key := make([]byte, sm4.BlockSize)
	rand.Reader.Read(key)

	var ptext = []byte("0123456789ABCDEF")

	for i := 1; i < sm4.BlockSize; i++ {
		ciphertext, err := SM4CBCPKCS7Encrypt(key, ptext[:i])
		if err != nil {
			t.Fatal("Error encrypting '", ptext, "'")
		}

		expectedLength := sm4.BlockSize + sm4.BlockSize
		if len(ciphertext) != expectedLength {
			t.Fatalf("Incorrect ciphertext incorrect: expected '%d', received '%d'", expectedLength, len(ciphertext))
		}
	}
}

func TestCBCEncryptCBCDecrypt_KeyMismatch(t *testing.T) {
	t.Parallel()

	// Generate a random key
	key := make([]byte, sm4.BlockSize)
	rand.Reader.Read(key)

	// Clone & tamper with the key
	wrongKey := make([]byte, sm4.BlockSize)
	copy(wrongKey, key[:])
	wrongKey[0] = key[0] + 1

	var ptext = []byte("1234567890ABCDEF")
	encrypted, encErr := sm4CBCEncrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %v", ptext, encErr)
	}

	decrypted, decErr := sm4CBCDecrypt(wrongKey, encrypted)
	if decErr != nil {
		t.Fatalf("Error decrypting '%s': %v", ptext, decErr)
	}

	if string(ptext[:]) == string(decrypted[:]) {
		t.Fatal("Decrypting a ciphertext with a different key than the one used for encrypting it - should not result in the original plaintext.")
	}
}

func TestCBCEncryptCBCDecrypt(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	rand.Reader.Read(key)

	//                  1234567890123456
	var ptext = []byte("a 16 byte messag")

	encrypted, encErr := sm4CBCEncrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %v", ptext, encErr)
	}

	decrypted, decErr := sm4CBCDecrypt(key, encrypted)
	if decErr != nil {
		t.Fatalf("Error decrypting '%s': %v", ptext, decErr)
	}

	if string(ptext[:]) != string(decrypted[:]) {
		t.Fatal("Encryption->Decryption with same key should result in the original plaintext.")
	}
}

func TestCBCEncryptWithRandCBCDecrypt(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	rand.Reader.Read(key)

	//                  1234567890123456
	var ptext = []byte("a 16 byte messag")

	encrypted, encErr := sm4CBCEncryptWithRand(rand.Reader, key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %v", ptext, encErr)
	}

	decrypted, decErr := sm4CBCDecrypt(key, encrypted)
	if decErr != nil {
		t.Fatalf("Error decrypting '%s': %v", ptext, decErr)
	}

	if string(ptext[:]) != string(decrypted[:]) {
		t.Fatal("Encryption->Decryption with same key should result in the original plaintext.")
	}
}

func TestCBCEncryptWithIVCBCDecrypt(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	rand.Reader.Read(key)

	//                  1234567890123456
	var ptext = []byte("a 16 byte messag")

	iv := make([]byte, sm4.BlockSize)
	_, err := io.ReadFull(rand.Reader, iv)
	assert.NoError(t, err)

	encrypted, encErr := sm4CBCEncryptWithIV(iv, key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %v", ptext, encErr)
	}

	decrypted, decErr := sm4CBCDecrypt(key, encrypted)
	if decErr != nil {
		t.Fatalf("Error decrypting '%s': %v", ptext, decErr)
	}

	if string(ptext[:]) != string(decrypted[:]) {
		t.Fatal("Encryption->Decryption with same key should result in the original plaintext.")
	}
}

func TestParallelSM4RelatedUtilFunctions(t *testing.T) {
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprintf("g-%d", i), TestSM4RelatedUtilFunctions)
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

	key, err := GetRandomBytes(16)
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

func TestPkcs7UnPaddingInvalidInputs(t *testing.T) {
	t.Parallel()

	_, err := pkcs7UnPadding([]byte{1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	assert.Error(t, err)
	assert.Equal(t, "Invalid pkcs7 padding (pad[i] != unpadding)", err.Error())
}

func TestSM4CBCEncryptInvalidInputs(t *testing.T) {
	t.Parallel()

	_, err := sm4CBCEncrypt(nil, []byte{0, 1, 2, 3})
	assert.Error(t, err)
	assert.Equal(t, "Invalid plaintext. It must be a multiple of the block size", err.Error())

	_, err = sm4CBCEncrypt([]byte{0}, []byte{1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	assert.Error(t, err)
}

func TestAESCBCDecryptInvalidInputs(t *testing.T) {
	t.Parallel()

	_, err := sm4CBCDecrypt([]byte{0}, []byte{1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	assert.Error(t, err)

	_, err = sm4CBCDecrypt([]byte{1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0})
	assert.Error(t, err)

	_, err = sm4CBCDecrypt([]byte{1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		[]byte{1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	assert.Error(t, err)
}

func TestSM4CBCPKCS7EncryptorDecrypt(t *testing.T) {
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

func TestSM4CBCPKCS7EncryptorWithIVSameCiphertext(t *testing.T) {
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
	assert.Equal(t, iv, ct[:sm4.BlockSize])

	ct2, err := encryptor.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{IV: iv})
	assert.NoError(t, err)
	assert.NotNil(t, ct2)
	assert.Equal(t, iv, ct2[:sm4.BlockSize])

	assert.Equal(t, ct, ct2)
}

func TestSM4CBCPKCS7EncryptorWithRandSameCiphertext(t *testing.T) {
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
	assert.Equal(t, iv, ct[:sm4.BlockSize])

	r = mrand.New(mrand.NewSource(0))
	ct2, err := encryptor.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{PRNG: r})
	assert.NoError(t, err)
	assert.NotNil(t, ct2)
	assert.Equal(t, iv, ct2[:sm4.BlockSize])

	assert.Equal(t, ct, ct2)
}
