package gm

import (
	"github.com/pkg/errors"
	"reflect"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm3"
)

func NewDefaultSecurityLevel(keyStorePath string) (bccsp.BCCSP, error) {
	ks := &fileBasedKeyStore{}
	if err := ks.Init(nil, keyStorePath, false); err != nil {
		return nil, errors.Wrapf(err, "Failed initializing key store at [%v]", keyStorePath)
	}

	return NewWithParams(-1, "SM", ks)
}

func NewWithParams(securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	conf := &config{}
	err := conf.setSecurityLevel(securityLevel, hashFamily)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing configuration at [%v,%v]", securityLevel, hashFamily)
	}

	gmbccsp, err := New(keyStore)
	if err != nil {
		return nil, err
	}

	// Notice that errors are ignored here because some test will fail if one
	// of the following call fails.

	// Set the Encryptors
	gmbccsp.AddWrapper(reflect.TypeOf(&sm4PrivateKey{}), &sm4cbcpkcs7Encryptor{})

	// Set the Decryptors
	gmbccsp.AddWrapper(reflect.TypeOf(&sm4PrivateKey{}), &sm4cbcpkcs7Decryptor{})

	// Set the Signers
	gmbccsp.AddWrapper(reflect.TypeOf(&sm2PrivateKey{}), &sm2Signer{})

	// Set the Verifiers
	gmbccsp.AddWrapper(reflect.TypeOf(&sm2PrivateKey{}), &sm2PrivateKeyVerifier{})
	gmbccsp.AddWrapper(reflect.TypeOf(&sm2PublicKey{}), &sm2PublicKeyKeyVerifier{})

	// Set the Hashers
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM3Opts{}), &hasher{hash: sm3.New})

	// Set the key generators
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2KeyGenOpts{}), &sm2KeyGenerator{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM4KeyGenOpts{}), &sm4KeyGenerator{length: 16})

	// Set the key deriver
	gmbccsp.AddWrapper(reflect.TypeOf(&sm2PrivateKey{}), &sm2PrivateKeyKeyDeriver{})
	gmbccsp.AddWrapper(reflect.TypeOf(&sm2PublicKey{}), &sm2PublicKeyKeyDeriver{})
	gmbccsp.AddWrapper(reflect.TypeOf(&sm4PrivateKey{}), &sm4PrivateKeyKeyDeriver{conf: conf})

	// Set the key importers
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM4ImportKeyOpts{}), &sm4ImportKeyOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2PKIXPublicKeyImportOpts{}), &sm2PKIXPublicKeyImportOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2PrivateKeyImportOpts{}), &sm2PrivateKeyImportOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2GoPublicKeyImportOpts{}), &sm2GoPublicKeyImportOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.X509PublicKeyImportOpts{}), &x509PublicKeyImportOptsKeyImporter{bccsp: gmbccsp})

	return gmbccsp, nil
}
