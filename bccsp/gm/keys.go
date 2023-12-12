package gm

import (
	"errors"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

func pemToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	return x509.ReadPrivateKeyFromPem(raw, pwd)
}

func privateKeyToPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	// Validate inputs
	if len(pwd) != 0 {
		return privateKeyToEncryptedPEM(privateKey, pwd)
	}
	if privateKey == nil {
		return nil, errors.New("invalid key. It must be different from nil")
	}

	switch k := privateKey.(type) {
	case *sm2.PrivateKey:
		if k == nil {
			return nil, errors.New("invalid sm2 private key. It must be different from nil")
		}

		return x509.WritePrivateKeyToPem(k, nil)

	default:
		return nil, errors.New("invalid key type. It must be *ecdsa.PrivateKey")
	}
}

func privateKeyToEncryptedPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("invalid private key. It must be different from nil")
	}

	switch k := privateKey.(type) {
	case *sm2.PrivateKey:
		if k == nil {
			return nil, errors.New("invalid sm2 private key. It must be different from nil")
		}
		return x509.WritePrivateKeyToPem(k, pwd)
	default:
		return nil, errors.New("invalid key type. It must be *ecdsa.PrivateKey")
	}
}

func publicKeyToPEM(publicKey interface{}) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("invalid public key. It must be different from nil")
	}

	switch k := publicKey.(type) {
	case *sm2.PublicKey:
		if k == nil {
			return nil, errors.New("invalid sm2 public key. It must be different from nil")
		}
		return x509.WritePublicKeyToPem(k)
	default:
		return nil, errors.New("invalid key type. It must be *sm2.PublicKey")
	}
}

func pemToPublicKey(raw []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM. It must be different from nil")
	}
	return x509.ReadPublicKeyFromPem(raw)
}
