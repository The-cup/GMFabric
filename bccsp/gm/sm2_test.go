/*
Copyright 2023 kasdect@163.com

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/x509"
)

func TestSignSM2BadParameter(t *testing.T) {
	lowLevelKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	// Induce an error on the underlying ecdsa algorithm
	curve := *sm2.P256Sm2().Params()
	curve.N = big.NewInt(0)
	lowLevelKey.Curve = &curve

	_, err = signSM2(lowLevelKey, []byte("hello world"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "zero parameter")
}

func TestVerifySM2(t *testing.T) {
	t.Parallel()

	// Generate a key
	lowLevelKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	msg := []byte("hello world")
	sigma, err := signSM2(lowLevelKey, msg, nil)
	assert.NoError(t, err)

	valid, err := verifySM2(&lowLevelKey.PublicKey, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	_, err = verifySM2(&lowLevelKey.PublicKey, nil, msg, nil)

	R, S, err := utils.UnmarshalSM2Signature(sigma)
	assert.NoError(t, err)
	S.Add(utils.GetCurveHalfOrdersAt(sm2.P256Sm2()), big.NewInt(1))
	sigmaWrongS, err := utils.MarshalSM2Signature(R, S)
	assert.NoError(t, err)
	_, err = verifySM2(&lowLevelKey.PublicKey, sigmaWrongS, msg, nil)
}

func TestSm2SignerSign(t *testing.T) {
	t.Parallel()

	signer := &sm2Signer{}
	verifierPrivateKey := &sm2PrivateKeyVerifier{}
	verifierPublicKey := &sm2PublicKeyKeyVerifier{}

	// Generate a key
	lowLevelKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	k := &sm2PrivateKey{lowLevelKey}
	pk, err := k.PublicKey()
	assert.NoError(t, err)

	// Sign
	msg := []byte("Hello World")
	sigma, err := signer.Sign(k, msg, nil)
	assert.NoError(t, err)
	assert.NotNil(t, sigma)

	// Verify
	valid, err := verifySM2(&lowLevelKey.PublicKey, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = verifierPrivateKey.Verify(k, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = verifierPublicKey.Verify(pk, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestSm2PrivateKey(t *testing.T) {
	t.Parallel()

	lowLevelKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	k := &sm2PrivateKey{lowLevelKey}

	assert.False(t, k.Symmetric())
	assert.True(t, k.Private())

	_, err = k.Bytes()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Not supported.")

	k.privKey = nil
	ski := k.SKI()
	assert.Nil(t, ski)

	k.privKey = lowLevelKey
	ski = k.SKI()
	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)
	hash := sm3.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	assert.Equal(t, ski2, ski, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, pk)
	sm2PK, ok := pk.(*sm2PublicKey)
	assert.True(t, ok)
	assert.Equal(t, &lowLevelKey.PublicKey, sm2PK.pubKey)
}

func TestSm2PublicKey(t *testing.T) {
	t.Parallel()

	lowLevelKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	k := &sm2PublicKey{&lowLevelKey.PublicKey}

	assert.False(t, k.Symmetric())
	assert.False(t, k.Private())

	k.pubKey = nil
	ski := k.SKI()
	assert.Nil(t, ski)

	k.pubKey = &lowLevelKey.PublicKey
	ski = k.SKI()
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)
	hash := sm3.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	assert.Equal(t, ski, ski2, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	assert.NoError(t, err)
	assert.Equal(t, k, pk)

	bytes, err := k.Bytes()
	assert.NoError(t, err)
	bytes2, err := x509.MarshalPKIXPublicKey(k.pubKey)
	assert.NoError(t, err)
	assert.Equal(t, bytes2, bytes, "bytes are not computed in the right way.")

	invalidCurve := &elliptic.CurveParams{Name: "P-Invalid"}
	invalidCurve.P = big.NewInt(1)
	invalidCurve.N = big.NewInt(1)
	invalidCurve.B = big.NewInt(1)
	invalidCurve.BitSize = 1024
	k.pubKey = &sm2.PublicKey{Curve: invalidCurve, X: big.NewInt(1), Y: big.NewInt(1)}

	defer func() {
		if r := recover(); r != nil {
			assert.Contains(t, r, "crypto/elliptic: attempted operation on invalid point")
		}
	}()
	_, err = k.Bytes()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed marshalling key [")
}
