package gm

import (
	"errors"

	"github.com/hyperledger/fabric/bccsp"
)

type sm2PublicKeyKeyDeriver struct{}

func (kd *sm2PublicKeyKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	sm2Key := &sm2KeyGenerator{}
	k, err := sm2Key.KeyGen(&SM2KeyGenOpts{})
	if err != nil {
		return nil, errors.New("sm2 key generate failed")
	}
	return k.PublicKey()
}

type sm2PrivateKeyKeyDeriver struct{}

func (kd *sm2PrivateKeyKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	sm2Key := &sm2KeyGenerator{}
	k, err := sm2Key.KeyGen(&SM2KeyGenOpts{})
	return k, err
}

type sm4PrivateKeyKeyDeriver struct {
}

func (kd *sm4PrivateKeyKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	keyPriv, err := key.Bytes()
	if err != nil {
		return nil, errors.New("sm4 private key key deriver failed")
	}
	sm4KeyGen := &sm4KeyGenerator{len(keyPriv)}
	return sm4KeyGen.KeyGen(&SM4KeyGenOpts{})
}
