/*
Copyright 2023 kasdect@163.com

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"crypto/rand"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm2"
)

func signSM2(k *sm2.PrivateKey, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	sign, err := k.Sign(rand.Reader, digest, nil)
	if err != nil {
		return nil, err
	}

	return sign, nil
}

func verifySM2(k *sm2.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	ok := k.Verify(digest, signature)
	return ok, nil
}

type sm2Signer struct{}

func (s *sm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return signSM2(k.(*sm2PrivateKey).privKey, digest, opts)
}

type sm2PrivateKeyVerifier struct{}

func (v *sm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifySM2(&(k.(*sm2PrivateKey).privKey.PublicKey), signature, digest, opts)
}

type sm2PublicKeyKeyVerifier struct{}

func (v *sm2PublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifySM2(k.(*sm2PublicKey).pubKey, signature, digest, opts)
}
