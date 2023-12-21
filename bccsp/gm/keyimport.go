package gm

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm2"
)

type sm4ImportKeyOptsKeyImporter struct{}

func (ki *sm4ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	sm4Raw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if sm4Raw == nil {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	if len(sm4Raw) != 16 {
		return nil, fmt.Errorf("Invalid Key Length [%d]. Must be 32 bytes", len(sm4Raw))
	}

	return &sm4PrivateKey{sm4Raw, false}, nil
}

type hmacImportKeyOptsKeyImporter struct{}

func (*hmacImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	sm4Raw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(sm4Raw) == 0 {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	return &sm4PrivateKey{sm4Raw, false}, nil
}

type sm2PKIXPublicKeyImportOptsKeyImporter struct{}

func (*sm2PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SM2 public key [%s]", err)
	}

	sm2PK, ok := lowLevelKey.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to SM2 public key. Invalid raw material.")
	}

	return &sm2PublicKey{sm2PK}, nil
}

type sm2PrivateKeyImportOptsKeyImporter struct{}

func (*sm2PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[SM2DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[SM2DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SM2 public key [%s]", err)
	}

	sm2SK, ok := lowLevelKey.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to SM2 private key. Invalid raw material.")
	}

	return &sm2PrivateKey{sm2SK}, nil
}

type sm2GoPublicKeyImportOptsKeyImporter struct{}

func (*sm2GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *sm2.PublicKey.")
	}

	return &sm2PublicKey{lowLevelKey}, nil
}

type x509PublicKeyImportOptsKeyImporter struct {
	bccsp *CSP
}

func (ki *x509PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *x509.Certificate.")
	}

	pk := x509Cert.PublicKey

	switch pk := pk.(type) {
	case *ecdsa.PublicKey:
		if pk.Curve == sm2.P256Sm2() {
			return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.SM2GoPublicKeyImportOpts{})].KeyImport(
				&sm2.PublicKey{
					Curve: pk.Curve,
					X:     pk.X,
					Y:     pk.Y,
				},
				&bccsp.SM2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
		}
		return nil, errors.New("Certificate's public key type not recognized. Supported keys: [SM2]")
	case *sm2.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.SM2GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.SM2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	default:
		return nil, errors.New("Certificate's public key type not recognized. Supported keys: [SM2]")
	}
}
