/*
Copyright 2023 kasdect@163.com

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"golang.org/x/crypto/sha3"
)

type config struct {
	ellipticCurve elliptic.Curve
	hashFunction  func() hash.Hash
	sm4BitLength  int
	aesBitLength  int
}

func (conf *config) setSecurityLevel(securityLevel int, hashFamily string) (err error) {
	switch hashFamily {
	case "SM":
		err = conf.setSecurityLevelSM()
	default:
		err = fmt.Errorf("Hash Family not supported [%s]", hashFamily)
	}
	return
}

func (conf *config) setSecurityLevelSHA2(level int) (err error) {
	switch level {
	case 256:
		conf.ellipticCurve = elliptic.P256()
		conf.hashFunction = sha256.New
		conf.aesBitLength = 32
	case 384:
		conf.ellipticCurve = elliptic.P384()
		conf.hashFunction = sha512.New384
		conf.aesBitLength = 32
	default:
		err = fmt.Errorf("Security level not supported [%d]", level)
	}
	return
}

func (conf *config) setSecurityLevelSHA3(level int) (err error) {
	switch level {
	case 256:
		conf.ellipticCurve = elliptic.P256()
		conf.hashFunction = sha3.New256
		conf.aesBitLength = 32
	case 384:
		conf.ellipticCurve = elliptic.P384()
		conf.hashFunction = sha3.New384
		conf.aesBitLength = 32
	default:
		err = fmt.Errorf("Security level not supported [%d]", level)
	}
	return
}

func (conf *config) setSecurityLevelSM() (err error) {
	conf.ellipticCurve = sm2.P256Sm2()
	conf.hashFunction = sm3.New
	conf.sm4BitLength = 16
	return nil
}
