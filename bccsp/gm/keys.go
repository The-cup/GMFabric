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
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"github.com/tjfoc/gmsm/sm4"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

var (
	oidNamedCurveP224    = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256    = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384    = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521    = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	case sm2.P256Sm2():
		return oidNamedCurveP256SM2, true
	}
	return nil, false
}

func privateKeyToDER(privateKey *sm2.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("invalid sm2 private key. It must be different from nil")
	}

	return x509.MarshalSm2PrivateKey(privateKey, nil)
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

func derToPrivateKey(der []byte) (key interface{}, err error) {

	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err = x509.ParsePKCS8PrivateKey(der, nil); err == nil {
		switch key.(type) {
		case *sm2.PrivateKey:
			return
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err = x509.ParseSm2PrivateKey(der); err == nil {
		return
	}

	return nil, errors.New("invalid key type. The DER must contain an sm2.PrivateKey")

}

func pemToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	if len(pwd) == 0 {
		return x509.ReadPrivateKeyFromPem(raw, nil)
	}
	return x509.ReadPrivateKeyFromPem(raw, pwd)
}

func pemToSM4(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM. It must be different from nil")
	}
	return sm4.ReadKeyFromPem(raw, pwd)
}

func sm4ToPEM(raw []byte) []byte {
	pem, err := sm4.WriteKeyToPem(raw, nil)
	if err != nil {
		return nil
	}
	return pem
}

func sm4ToEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid aes key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return sm4ToPEM(raw), nil
	}
	return sm4.WriteKeyToPem(raw, pwd)
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

func derToPublicKey(raw []byte) (pub interface{}, err error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid DER. It must be different from nil")
	}

	if key, err := x509.ParseSm2PublicKey(raw); err == nil {
		return key, err
	}

	key, err := x509.ParsePKIXPublicKey(raw)

	return key, err
}
