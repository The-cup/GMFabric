package utils

import (
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

func ReadPrivateKeyFromPem(privateKeyPem []byte, pwd []byte) (*sm2.PrivateKey, error) {
	return x509.ReadPrivateKeyFromPem(privateKeyPem, pwd)
}

func WritePrivateKeyToPem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	return x509.WritePrivateKeyToPem(key, pwd)
}

func WritePublicKeyToPem(key *sm2.PublicKey) ([]byte, error) {
	return x509.WritePublicKeyToPem(key)
}

func MarshalSm2PrivateKey(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	return x509.MarshalSm2PrivateKey(key, pwd)
}

func ParsePKCS8PrivateKey(der, pwd []byte) (*sm2.PrivateKey, error) {
	return x509.ParsePKCS8PrivateKey(der, pwd)
}

func ParseSm2PrivateKey(der []byte) (*sm2.PrivateKey, error) {
	return x509.ParseSm2PrivateKey(der)
}

func ParseSm2PublicKey(der []byte) (*sm2.PublicKey, error) {
	return x509.ParseSm2PublicKey(der)
}

func MarshalSm2PublicKey(key *sm2.PublicKey) ([]byte, error) {
	return x509.MarshalSm2PublicKey(key)
}
