package gm

import (
	"crypto/rand"
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm2"
)

type sm2KeyGenerator struct{}

func (kg *sm2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed generating sm2 key: [%s]", err)
	}

	return &sm2PrivateKey{privKey}, nil
}

type sm4KeyGenerator struct {
	length int
}

func (kg *sm4KeyGenerator) KeyGen(ops bccsp.KeyGenOpts) (bccsp.Key, error) {
	lowLevelKey, err := GetRandomBytes(int(kg.length))
	if err != nil {
		return nil, fmt.Errorf("Failed generating AES %d key [%s]", kg.length, err)
	}

	return &sm4PrivateKey{lowLevelKey, false}, nil
}
