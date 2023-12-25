/*
Copyright 2023 kasdect@163.com

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"

	"github.com/hyperledger/fabric/bccsp"
)

type sm2PublicKeyKeyDeriver struct{}

func (kd *sm2PublicKeyKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	sm2K := key.(*sm2PublicKey)

	// Re-randomized an ECDSA private key
	reRandOpts, ok := opts.(*bccsp.SM2ReRandKeyOpts)
	if !ok {
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}

	tempSK := &sm2.PublicKey{
		Curve: sm2K.pubKey.Curve,
		X:     new(big.Int),
		Y:     new(big.Int),
	}

	var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
	var one = new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(sm2K.pubKey.Params().N, one)
	k.Mod(k, n)
	k.Add(k, one)

	// Compute temporary public key
	tempX, tempY := sm2K.pubKey.ScalarBaseMult(k.Bytes())
	tempSK.X, tempSK.Y = tempSK.Add(
		sm2K.pubKey.X, sm2K.pubKey.Y,
		tempX, tempY,
	)

	// Verify temporary public key is a valid point on the reference curve
	isOn := tempSK.Curve.IsOnCurve(tempSK.X, tempSK.Y)
	if !isOn {
		return nil, errors.New("Failed temporary public key IsOnCurve check.")
	}

	return &sm2PublicKey{tempSK}, nil

}

type sm2PrivateKeyKeyDeriver struct{}

func (kd *sm2PrivateKeyKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	sm2K := key.(*sm2PrivateKey)

	// Re-randomized an ECDSA private key
	reRandOpts, ok := opts.(*bccsp.SM2ReRandKeyOpts)
	if !ok {
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}

	tempSK := &sm2.PrivateKey{
		PublicKey: sm2.PublicKey{
			Curve: sm2K.privKey.Curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		},
		D: new(big.Int),
	}

	var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
	var one = new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(sm2K.privKey.Params().N, one)
	k.Mod(k, n)
	k.Add(k, one)

	tempSK.D.Add(sm2K.privKey.D, k)
	tempSK.D.Mod(tempSK.D, sm2K.privKey.PublicKey.Params().N)

	// Compute temporary public key
	tempX, tempY := sm2K.privKey.PublicKey.ScalarBaseMult(k.Bytes())
	tempSK.PublicKey.X, tempSK.PublicKey.Y =
		tempSK.PublicKey.Add(
			sm2K.privKey.PublicKey.X, sm2K.privKey.PublicKey.Y,
			tempX, tempY,
		)

	// Verify temporary public key is a valid point on the reference curve
	isOn := tempSK.Curve.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y)
	if !isOn {
		return nil, errors.New("Failed temporary public key IsOnCurve check.")
	}

	return &sm2PrivateKey{tempSK}, nil
}

type sm4PrivateKeyKeyDeriver struct {
	conf *config
}

func (kd *sm4PrivateKeyKeyDeriver) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	sm4K := k.(*sm4PrivateKey)

	switch hmacOpts := opts.(type) {
	case *bccsp.HMACTruncated256SM4DeriveKeyOpts:
		mac := hmac.New(kd.conf.hashFunction, sm4K.privKey)
		mac.Write(hmacOpts.Argument())
		return &sm4PrivateKey{mac.Sum(nil)[:kd.conf.sm4BitLength], false}, nil

	case *bccsp.HMACDeriveKeyOpts:
		mac := hmac.New(kd.conf.hashFunction, sm4K.privKey)
		mac.Write(hmacOpts.Argument())
		return &sm4PrivateKey{mac.Sum(nil), true}, nil

	default:
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}
}
