package gm

import (
	"crypto/rand"
	"testing"

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
	const expectedLength = sm4.BlockSize + sm4.BlockSize
	if len(ciphertext) != expectedLength {
		t.Fatalf("Wrong ciphertext length. Expected %d, received %d", expectedLength, len(ciphertext))
	}

	t.Log("Ciphertext length: ", len(ciphertext))
	t.Log("Cipher: ", ciphertext)
}
