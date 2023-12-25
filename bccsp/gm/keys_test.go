/*
Copyright 2023 kasdect@163.com

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"github.com/tjfoc/gmsm/x509"
)

func TestOidFromNamedCurve(t *testing.T) {
	var (
		oidNamedCurveP224    = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
		oidNamedCurveP256    = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
		oidNamedCurveP384    = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
		oidNamedCurveP521    = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
		oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
	)

	type result struct {
		oid asn1.ObjectIdentifier
		ok  bool
	}

	var tests = []struct {
		name     string
		curve    elliptic.Curve
		expected result
	}{
		{
			name:  "P224",
			curve: elliptic.P224(),
			expected: result{
				oid: oidNamedCurveP224,
				ok:  true,
			},
		},
		{
			name:  "P256",
			curve: elliptic.P256(),
			expected: result{
				oid: oidNamedCurveP256,
				ok:  true,
			},
		},
		{
			name:  "P384",
			curve: elliptic.P384(),
			expected: result{
				oid: oidNamedCurveP384,
				ok:  true,
			},
		},
		{
			name:  "P521",
			curve: elliptic.P521(),
			expected: result{
				oid: oidNamedCurveP521,
				ok:  true,
			},
		},
		{
			name:  "P256SM2",
			curve: sm2.P256Sm2(),
			expected: result{
				oid: oidNamedCurveP256SM2,
				ok:  true,
			},
		},
		{
			name:  "T-1000",
			curve: &elliptic.CurveParams{Name: "T-1000"},
			expected: result{
				oid: nil,
				ok:  false,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oid, ok := oidFromNamedCurve(test.curve)
			assert.Equal(t, oid, test.expected.oid)
			assert.Equal(t, ok, test.expected.ok)
		})
	}

}

func TestSM2Keys(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	// Private Key DER format
	der, err := privateKeyToDER(key)
	if err != nil {
		t.Fatalf("Failed converting private key to DER [%s]", err)
	}
	keyFromDER, err := derToPrivateKey(der)
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	sm2KeyFromDer := keyFromDER.(*sm2.PrivateKey)
	// TODO: check the curve
	if key.D.Cmp(sm2KeyFromDer.D) != 0 {
		t.Fatal("Failed converting DER to private key. Invalid D.")
	}
	if key.X.Cmp(sm2KeyFromDer.X) != 0 {
		t.Fatal("Failed converting DER to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(sm2KeyFromDer.Y) != 0 {
		t.Fatal("Failed converting DER to private key. Invalid Y coordinate.")
	}

	// Private Key PEM format
	rawPEM, err := privateKeyToPEM(key, nil)
	if err != nil {
		t.Fatalf("Failed converting private key to PEM [%s]", err)
	}
	pemBlock, _ := pem.Decode(rawPEM)
	if pemBlock.Type != "PRIVATE KEY" {
		t.Fatalf("Expected type 'PRIVATE KEY' but found '%s'", pemBlock.Type)
	}
	_, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes, nil)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#8 private key [%s]", err)
	}
	keyFromPEM, err := pemToPrivateKey(rawPEM, nil)
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	sm2KeyFromPEM := keyFromPEM.(*sm2.PrivateKey)
	// TODO: check the curve
	if key.D.Cmp(sm2KeyFromPEM.D) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid D.")
	}
	if key.X.Cmp(sm2KeyFromPEM.X) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(sm2KeyFromPEM.Y) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
	}

	// Nil Private Key <-> PEM
	_, err = privateKeyToPEM(nil, nil)
	if err == nil {
		t.Fatal("PublicKeyToPEM should fail on nil")
	}

	_, err = privateKeyToPEM((*sm2.PrivateKey)(nil), nil)
	if err == nil {
		t.Fatal("PrivateKeyToPEM should fail on nil")
	}

	_, err = pemToPrivateKey(nil, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil")
	}

	_, err = pemToPrivateKey([]byte{0, 1, 3, 4}, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail invalid PEM")
	}

	_, err = derToPrivateKey(nil)
	if err == nil {
		t.Fatal("DERToPrivateKey should fail on nil")
	}

	_, err = derToPrivateKey([]byte{0, 1, 3, 4})
	if err == nil {
		t.Fatal("DERToPrivateKey should fail on invalid DER")
	}

	_, err = privateKeyToDER(nil)
	if err == nil {
		t.Fatal("DERToPrivateKey should fail on nil")
	}

	// Private Key Encrypted PEM format
	encPEM, err := privateKeyToPEM(key, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting private key to encrypted PEM [%s]", err)
	}
	_, err = pemToPrivateKey(encPEM, nil)
	assert.Error(t, err)
	encKeyFromPEM, err := pemToPrivateKey(encPEM, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	sm2KeyFromEncPEM := encKeyFromPEM.(*sm2.PrivateKey)
	// TODO: check the curve
	if key.D.Cmp(sm2KeyFromEncPEM.D) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid D.")
	}
	if key.X.Cmp(sm2KeyFromEncPEM.X) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(sm2KeyFromEncPEM.Y) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid Y coordinate.")
	}

	// Public Key PEM format
	rawPEM, err = publicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("Failed converting public key to PEM [%s]", err)
	}
	pemBlock, _ = pem.Decode(rawPEM)
	if pemBlock.Type != "PUBLIC KEY" {
		t.Fatalf("Expected type 'PUBLIC KEY' but found '%s'", pemBlock.Type)
	}
	keyFromPEM, err = pemToPublicKey(rawPEM)
	if err != nil {
		t.Fatalf("Failed converting DER to public key [%s]", err)
	}
	sm2PkFromPEM := keyFromPEM.(*sm2.PublicKey)
	// TODO: check the curve
	if key.X.Cmp(sm2PkFromPEM.X) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(sm2PkFromPEM.Y) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
	}

	// Nil Public Key <-> PEM
	_, err = publicKeyToPEM(nil)
	if err == nil {
		t.Fatal("PublicKeyToPEM should fail on nil")
	}

	_, err = pemToPublicKey(nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil")
	}

	_, err = pemToPublicKey([]byte{0, 1, 3, 4})
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on invalid PEM")
	}

	// Public Key DER format
	der, err = x509.MarshalSm2PublicKey(&key.PublicKey)
	assert.NoError(t, err)
	keyFromDER, err = derToPublicKey(der)
	assert.NoError(t, err)
	sm2PkFromPEM = keyFromDER.(*sm2.PublicKey)
	// TODO: check the curve
	if key.X.Cmp(sm2PkFromPEM.X) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(sm2PkFromPEM.Y) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
	}
}

func TestSM4Key(t *testing.T) {
	k := sm4.SM4Key{0, 1, 2, 3, 4, 5}
	pem, err := sm4.WriteKeyToPem(k, nil)
	assert.NoError(t, err)

	k2, err := sm4.ReadKeyFromPem(pem, nil)
	assert.NoError(t, err)
	assert.Equal(t, k, k2)

	pem, err = sm4.WriteKeyToPem(k, k)
	assert.NoError(t, err)

	k2, err = sm4.ReadKeyFromPem(pem, k)
	assert.NoError(t, err)
	assert.Equal(t, k, k2)

	_, err = sm4.ReadKeyFromPem(pem, nil)
	assert.Error(t, err)

	_, err = sm4.WriteKeyToPem(k, nil)
	assert.NoError(t, err)

	k2, err = sm4.ReadKeyFromPem(pem, k)
	assert.NoError(t, err)
	assert.Equal(t, k, k2)
}

func TestNil(t *testing.T) {
	_, err := privateKeyToEncryptedPEM(nil, nil)
	assert.Error(t, err)

	_, err = privateKeyToEncryptedPEM((*sm2.PrivateKey)(nil), nil)
	assert.Error(t, err)

	_, err = privateKeyToEncryptedPEM("Hello World", nil)
	assert.Error(t, err)

	_, err = sm4.ReadKeyFromPem(nil, nil)
	assert.Error(t, err)

	_, err = publicKeyToPEM(nil)
	assert.Error(t, err)
	_, err = publicKeyToPEM((*sm2.PublicKey)(nil))
	assert.Error(t, err)

	_, err = publicKeyToPEM("hello world")
	assert.Error(t, err)

}
