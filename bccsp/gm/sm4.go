package gm

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm4"
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

func sm4CBCEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	if len(s)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	ciphertext := make([]byte, sm4.BlockSize+len(s))
	iv := ciphertext[:sm4.BlockSize]
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}

	sm4.SetIV(iv)
	ciphertext, err := sm4.Sm4Cbc(key, s, true)
	if err != nil {
		return nil, errors.New("Sm4Cbc function failed")
	}
	return ciphertext, nil
}

func sm4CBCEncryptWithIV(IV []byte, key, s []byte) ([]byte, error) {
	if len(s)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	if len(IV) != sm4.BlockSize {
		return nil, errors.New("Invalid IV. It must have length the block size")
	}

	sm4.SetIV(IV)
	ciphertext, err := sm4.Sm4Cbc(key, s, true)
	if err != nil {
		return nil, errors.New("Sm4Cbc function failed")
	}

	return ciphertext, nil
}

func SM4CBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	return SM4CBCPKCS7EncryptWithRand(rand.Reader, key, src)
}

func SM4CBCPKCS7EncryptWithRand(prng io.Reader, key, src []byte) ([]byte, error) {
	return sm4CBCEncryptWithRand(prng, key, src)
}

func SM4CBCPKCS7EncryptWithIV(IV []byte, key, src []byte) ([]byte, error) {
	return sm4CBCEncryptWithIV(IV, key, src)
}

type sm4cbcEncryptor struct{}

func (e *sm4cbcEncryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
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
