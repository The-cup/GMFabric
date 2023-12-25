/*
Copyright 2023 kasdect@163.com

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric/bccsp/sw/mocks"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/x509"
)

var (
	currentTestConfig testConfig
	tempDir           string
)

type testConfig struct {
	securityLevel int
	hashFamily    string
}

func (tc testConfig) Provider(t *testing.T) (bccsp.BCCSP, bccsp.KeyStore, func()) {
	td, err := ioutil.TempDir(tempDir, "test")
	assert.NoError(t, err)
	ks, err := NewFileBasedKeyStore(nil, td, false)
	assert.NoError(t, err)
	p, err := NewWithParams(tc.securityLevel, tc.hashFamily, ks)
	assert.NoError(t, err)
	return p, ks, func() { os.RemoveAll(td) }
}

func TestMain(m *testing.M) {
	code := -1
	defer func() {
		os.Exit(code)
	}()
	tests := []testConfig{
		{-1, "SM"},
	}

	var err error
	tempDir, err = ioutil.TempDir("", "bccsp-gm")
	if err != nil {
		fmt.Printf("Failed to create temporary directory: %s\n\n", err)
		return
	}
	defer os.RemoveAll(tempDir)

	for _, config := range tests {
		currentTestConfig = config
		code = m.Run()
		if code != 0 {
			fmt.Printf("Failed testing at [%d, %s]", config.securityLevel, config.hashFamily)
			return
		}
	}
}

func TestInvalidNewParameter(t *testing.T) {
	t.Parallel()
	_, ks, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	r, err := NewWithParams(0, "SHA2", ks)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if r != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	r, err = NewWithParams(256, "SHA8", ks)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if r != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	r, err = NewWithParams(256, "SHA2", nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if r != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	r, err = NewWithParams(0, "SHA3", nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if r != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	r, err = NewDefaultSecurityLevel("")
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if r != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}

func TestInvalidSKI(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.GetKey(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	k, err = provider.GetKey([]byte{0, 1, 2, 3, 4, 5, 6})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}

func TestKeyGenSM2Opts(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 P256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM2 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating SM2 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating SM2 key. Key should be asymmetric")
	}

	sm2Key := k.(*sm2PrivateKey).privKey
	if !sm2.P256Sm2().IsOnCurve(sm2Key.X, sm2Key.Y) {
		t.Fatal("P256Sm2 generated key in invalid. The public key must be on the P256Sm2 curve.")
	}
	if sm2.P256Sm2() != sm2Key.Curve {
		t.Fatal("P256Sm2 generated key in invalid. The curve must be P256Sm2.")
	}
	if sm2Key.D.Cmp(big.NewInt(0)) == 0 {
		t.Fatal("P256Sm2 generated key in invalid. Private key must be different from 0.")
	}
}

func TestKeyGenSM4Opts(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM4KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM4 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating SM4 key. Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed generating SM4 key. Key should be symmetric")
	}

	sm4Key := k.(*sm4PrivateKey).privKey
	if len(sm4Key) != 16 {
		t.Fatal("SM4 Key generated key in invalid. The key must have length 16.")
	}
}

func TestSM2KeyGenEphemeral(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: true})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM2 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating SM2 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating SM2 key. Key should be asymmetric")
	}
	raw, err := k.Bytes()
	if err == nil {
		t.Fatal("Failed marshalling to bytes. Marshalling must fail.")
	}
	if len(raw) != 0 {
		t.Fatal("Failed marshalling to bytes. Output should be 0 bytes")
	}
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting corresponding public key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Public key must be different from nil.")
	}
}

func TestSM2PrivateKeySKI(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	ski := k.SKI()
	if len(ski) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}
}

func TestSM2KeyGenNonEphemeral(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM2 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating SM2 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating SM2 key. Key should be asymmetric")
	}
}

func TestSM2GetKeyBySKI(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	k2, err := provider.GetKey(k.SKI())
	if err != nil {
		t.Fatalf("Failed getting SM2 key [%s]", err)
	}
	if k2 == nil {
		t.Fatal("Failed getting SM2 key. Key must be different from nil")
	}
	if !k2.Private() {
		t.Fatal("Failed getting SM2 key. Key should be private")
	}
	if k2.Symmetric() {
		t.Fatal("Failed getting SM2 key. Key should be asymmetric")
	}

	// Check that the SKIs are the same
	if !bytes.Equal(k.SKI(), k2.SKI()) {
		t.Fatalf("SKIs are different [%x]!=[%x]", k.SKI(), k2.SKI())
	}
}

func TestSM2PublicKeyFromPrivateKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private SM2 key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Failed getting public key from private SM2 key. Key must be different from nil")
	}
	if pk.Private() {
		t.Fatal("Failed generating SM2 key. Key should be public")
	}
	if pk.Symmetric() {
		t.Fatal("Failed generating SM2 key. Key should be asymmetric")
	}
}

func TestSM2PublicKeyBytes(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private SM2 key [%s]", err)
	}

	raw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed marshalling SM2 public key [%s]", err)
	}
	if len(raw) == 0 {
		t.Fatal("Failed marshalling SM2 public key. Zero length")
	}
}

func TestSM2PublicKeySKI(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private SM2 key [%s]", err)
	}

	ski := pk.SKI()
	if len(ski) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}
}

func TestSM2KeyReRand(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed re-randomizing SM2 key. Re-randomized Key must be different from nil")
	}

	reRandomizedKey, err := provider.KeyDeriv(k, &bccsp.SM2ReRandKeyOpts{Temporary: false, Expansion: []byte{1}})
	if err != nil {
		t.Fatalf("Failed re-randomizing SM2 key [%s]", err)
	}
	if !reRandomizedKey.Private() {
		t.Fatal("Failed re-randomizing SM2 key. Re-randomized Key should be private")
	}
	if reRandomizedKey.Symmetric() {
		t.Fatal("Failed re-randomizing SM2 key. Re-randomized Key should be asymmetric")
	}

	k2, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public SM2 key from private [%s]", err)
	}
	if k2 == nil {
		t.Fatal("Failed re-randomizing SM2 key. Re-randomized Key must be different from nil")
	}

	reRandomizedKey2, err := provider.KeyDeriv(k2, &bccsp.SM2ReRandKeyOpts{Temporary: false, Expansion: []byte{1}})
	if err != nil {
		t.Fatalf("Failed re-randomizing SM2 key [%s]", err)
	}

	if reRandomizedKey2.Private() {
		t.Fatal("Re-randomized public Key must remain public")
	}
	if reRandomizedKey2.Symmetric() {
		t.Fatal("Re-randomized SM2 asymmetric key must remain asymmetric")
	}

	if false == bytes.Equal(reRandomizedKey.SKI(), reRandomizedKey2.SKI()) {
		t.Fatal("Re-randomized SM2 Private- or Public-Keys must end up having the same SKI")
	}
}

func TestSM2Sign(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}
	if len(signature) == 0 {
		t.Fatal("Failed generating SM2 key. Signature must be different from nil")
	}
}

func TestSM2Verify(t *testing.T) {
	t.Parallel()
	provider, ks, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}

	valid, err := provider.Verify(k, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting corresponding public key [%s]", err)
	}

	valid, err = provider.Verify(pk, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}

	// Store public key
	err = ks.StoreKey(pk)
	if err != nil {
		t.Fatalf("Failed storing corresponding public key [%s]", err)
	}

	pk2, err := ks.GetKey(pk.SKI())
	if err != nil {
		t.Fatalf("Failed retrieving corresponding public key [%s]", err)
	}

	valid, err = provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}

func TestSM2KeyDeriv(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	reRandomizedKey, err := provider.KeyDeriv(k, &bccsp.SM2ReRandKeyOpts{Temporary: false, Expansion: []byte{1}})
	if err != nil {
		t.Fatalf("Failed re-randomizing SM2 key [%s]", err)
	}

	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(reRandomizedKey, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}

	valid, err := provider.Verify(reRandomizedKey, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}

func TestSM2KeyImportFromExportedKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	// Generate an SM2 key
	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting SM2 public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting SM2 raw public key [%s]", err)
	}

	// Import the exported public key
	pk2, err := provider.KeyImport(pkRaw, &bccsp.SM2PKIXPublicKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing SM2 public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing SM2 public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}

	valid, err := provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}

func TestSM2KeyImportFromSM2PublicKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	// Generate an SM2 key
	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting SM2 public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting SM2 raw public key [%s]", err)
	}
	pub, err := derToPublicKey(pkRaw)
	if err != nil {
		t.Fatalf("Failed converting raw to sm2.PublicKey [%s]", err)
	}

	// Import the sm2.PublicKey
	pk2, err := provider.KeyImport(pub, &bccsp.SM2GoPublicKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing SM2 public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing SM2 public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}

	valid, err := provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}

func TestSM2KeyImportFromSM2PrivateKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	// Generate an SM2 key, default is P256Sm2
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	// Import the sm2.PrivateKey
	priv, err := privateKeyToDER(key)
	if err != nil {
		t.Fatalf("Failed converting raw to sm2.PrivateKey [%s]", err)
	}

	sk, err := provider.KeyImport(priv, &bccsp.SM2PrivateKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing SM2 private key [%s]", err)
	}
	if sk == nil {
		t.Fatal("Failed importing SM2 private key. Return BCCSP key cannot be nil.")
	}

	// Import the sm2.PublicKey
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("Failed converting raw to sm2.PublicKey [%s]", err)
	}

	pk, err := provider.KeyImport(pub, &bccsp.SM2PKIXPublicKeyImportOpts{Temporary: false})

	if err != nil {
		t.Fatalf("Failed importing SM2 public key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Failed importing SM2 public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(sk, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}

	valid, err := provider.Verify(pk, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}

func TestKeyImportFromX509SM2PublicKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	// Generate an SM2 key
	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	// Generate a self-signed certificate
	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Σ Acme Co"},
			Country:      []string{"US"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),

		SignatureAlgorithm: x509.SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocurrentBCCSP.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
		},
	}

	cryptoSigner, err := signer.NewSm2Signer(provider, k)
	if err != nil {
		t.Fatalf("Failed initializing CyrptoSigner [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting SM2 public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting SM2 raw public key [%s]", err)
	}

	pub, err := derToPublicKey(pkRaw)
	if err != nil {
		t.Fatalf("Failed converting raw to SM2.PublicKey [%s]", err)
	}

	certRaw, err := x509.CreateCertificate(&template, &template, pub.(*sm2.PublicKey), cryptoSigner)
	if err != nil {
		t.Fatalf("Failed generating self-signed certificate [%s]", err)
	}

	cert, err := x509.ParseSm2CertifateToX509(certRaw)
	if err != nil {
		t.Fatalf("Failed generating X509 certificate object from raw [%s]", err)
	}

	// Import the certificate's public key
	pk2, err := provider.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: false})

	if err != nil {
		t.Fatalf("Failed importing SM2 public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing SM2 public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}

	valid, err := provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}

func TestSM2SignatureEncoding(t *testing.T) {
	t.Parallel()

	v := []byte{0x30, 0x07, 0x02, 0x01, 0x8F, 0x02, 0x02, 0xff, 0xf1}
	_, err := asn1.Unmarshal(v, &utils.SM2Signature{})
	if err == nil {
		t.Fatalf("Unmarshalling should fail for [% x]", v)
	}
	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

	v = []byte{0x30, 0x07, 0x02, 0x01, 0x8F, 0x02, 0x02, 0x00, 0x01}
	_, err = asn1.Unmarshal(v, &utils.SM2Signature{})
	if err == nil {
		t.Fatalf("Unmarshalling should fail for [% x]", v)
	}
	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

	v = []byte{0x30, 0x07, 0x02, 0x01, 0x8F, 0x02, 0x81, 0x01, 0x01}
	_, err = asn1.Unmarshal(v, &utils.SM2Signature{})
	if err == nil {
		t.Fatalf("Unmarshalling should fail for [% x]", v)
	}
	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

	v = []byte{0x30, 0x07, 0x02, 0x01, 0x8F, 0x02, 0x81, 0x01, 0x8F}
	_, err = asn1.Unmarshal(v, &utils.SM2Signature{})
	if err == nil {
		t.Fatalf("Unmarshalling should fail for [% x]", v)
	}
	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

	v = []byte{0x30, 0x0A, 0x02, 0x01, 0x8F, 0x02, 0x05, 0x00, 0x00, 0x00, 0x00, 0x8F}
	_, err = asn1.Unmarshal(v, &utils.SM2Signature{})
	if err == nil {
		t.Fatalf("Unmarshalling should fail for [% x]", v)
	}
	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

}

//func TestSM2LowS(t *testing.T) {
//	t.Parallel()
//	provider, _, cleanup := currentTestConfig.Provider(t)
//	defer cleanup()
//
//	// Ensure that signature with low-S are generated
//	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
//	if err != nil {
//		t.Fatalf("Failed generating SM2 key [%s]", err)
//	}
//
//	msg := []byte("Hello World")
//
//	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
//	if err != nil {
//		t.Fatalf("Failed computing HASH [%s]", err)
//	}
//
//	signature, err := provider.Sign(k, digest, nil)
//	if err != nil {
//		t.Fatalf("Failed generating SM2 signature [%s]", err)
//	}
//
//	_, S, err := utils.UnmarshalSM2Signature(signature)
//	if err != nil {
//		t.Fatalf("Failed unmarshalling signature [%s]", err)
//	}
//
//	if S.Cmp(utils.GetCurveHalfOrdersAt(k.(*sm2PrivateKey).privKey.Curve)) >= 0 {
//		t.Fatal("Invalid signature. It must have low-S")
//	}
//
//	valid, err := provider.Verify(k, signature, digest, nil)
//	if err != nil {
//		t.Fatalf("Failed verifying SM2 signature [%s]", err)
//	}
//	if !valid {
//		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
//	}
//
//	// Ensure that signature with high-S are rejected.
//	var R *big.Int
//	for {
//		R, S, err = sm2.Sm2Sign(k.(*sm2PrivateKey).privKey, digest, nil, rand.Reader)
//		if err != nil {
//			t.Fatalf("Failed generating signature [%s]", err)
//		}
//
//		if S.Cmp(utils.GetCurveHalfOrdersAt(k.(*sm2PrivateKey).privKey.Curve)) > 0 {
//			break
//		}
//	}
//
//	sig, err := utils.MarshalSM2Signature(R, S)
//	if err != nil {
//		t.Fatalf("Failing unmarshalling signature [%s]", err)
//	}
//
//	valid, err = provider.Verify(k, sig, digest, nil)
//	if err == nil {
//		t.Fatal("Failed verifying SM2 signature. It must fail for a signature with high-S")
//	}
//	if valid {
//		t.Fatal("Failed verifying SM2 signature. It must fail for a signature with high-S")
//	}
//}

func TestSM4KeyGen(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM4KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM4 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating SM4 key. Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed generating SM4 key. Key should be symmetric")
	}

	pk, err := k.PublicKey()
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if pk != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}

func TestSM4Decrypt(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM4KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}

	msg := []byte("Hello World")

	ct, err := provider.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}

	pt, err := provider.Decrypt(k, ct, bccsp.SM4CBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed decrypting. Nil plaintext")
	}

	if !bytes.Equal(msg, pt) {
		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
	}
}

func TestHMACTruncated256KeyDerivOverSM4256Key(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM4KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}

	hmcaedKey, err := provider.KeyDeriv(k, &bccsp.HMACTruncated256SM4DeriveKeyOpts{Temporary: false, Arg: []byte{1}})
	if err != nil {
		t.Fatalf("Failed HMACing SM4 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed HMACing SM4 key. HMACed Key must be different from nil")
	}
	if !hmcaedKey.Private() {
		t.Fatal("Failed HMACing SM4 key. HMACed Key should be private")
	}
	if !hmcaedKey.Symmetric() {
		t.Fatal("Failed HMACing SM4 key. HMACed Key should be asymmetric")
	}
	raw, err := hmcaedKey.Bytes()
	if err == nil {
		t.Fatal("Failed marshalling to bytes. Operation must be forbidden")
	}
	if len(raw) != 0 {
		t.Fatal("Failed marshalling to bytes. Operation must return 0 bytes")
	}

	msg := []byte("Hello World")

	ct, err := provider.Encrypt(hmcaedKey, msg, &bccsp.SM4CBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}

	pt, err := provider.Decrypt(hmcaedKey, ct, bccsp.SM4CBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed decrypting. Nil plaintext")
	}

	if !bytes.Equal(msg, pt) {
		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
	}
}

func TestSM4KeyImport(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	raw, err := GetRandomBytes(16)
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}

	k, err := provider.KeyImport(raw, &bccsp.SM4ImportKeyOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing SM4 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed importing SM4 key. Imported Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed HMACing SM4 key. Imported Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed HMACing SM4 key. Imported Key should be asymmetric")
	}
	raw, err = k.Bytes()
	if err == nil {
		t.Fatal("Failed marshalling to bytes. Marshalling must fail.")
	}
	if len(raw) != 0 {
		t.Fatal("Failed marshalling to bytes. Output should be 0 bytes")
	}

	msg := []byte("Hello World")

	ct, err := provider.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}

	pt, err := provider.Decrypt(k, ct, bccsp.SM4CBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed decrypting. Nil plaintext")
	}

	if !bytes.Equal(msg, pt) {
		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
	}
}

func TestSM4KeyImportBadPaths(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	_, err := provider.KeyImport(nil, &bccsp.SM4ImportKeyOpts{Temporary: false})
	if err == nil {
		t.Fatal("Failed importing key. Must fail on importing nil key")
	}

	_, err = provider.KeyImport([]byte{1}, &bccsp.SM4ImportKeyOpts{Temporary: false})
	if err == nil {
		t.Fatal("Failed importing key. Must fail on importing a key with an invalid length")
	}
}

func TestSM4KeyGenSKI(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM4KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}

	k2, err := provider.GetKey(k.SKI())
	if err != nil {
		t.Fatalf("Failed getting SM4 key [%s]", err)
	}
	if k2 == nil {
		t.Fatal("Failed getting SM4 key. Key must be different from nil")
	}
	if !k2.Private() {
		t.Fatal("Failed getting SM4 key. Key should be private")
	}
	if !k2.Symmetric() {
		t.Fatal("Failed getting SM4 key. Key should be symmetric")
	}

	// Check that the SKIs are the same
	if !bytes.Equal(k.SKI(), k2.SKI()) {
		t.Fatalf("SKIs are different [%x]!=[%x]", k.SKI(), k2.SKI())
	}
}

func TestSM3(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	for i := 0; i < 100; i++ {
		b, err := GetRandomBytes(i)
		if err != nil {
			t.Fatalf("Failed getting random bytes [%s]", err)
		}

		h1, err := provider.Hash(b, &bccsp.SM3Opts{})
		if err != nil {
			t.Fatalf("Failed computing SM3 [%s]", err)
		}

		var h hash.Hash
		switch currentTestConfig.hashFamily {
		case "SM":
			h = sm3.New()
		default:
			t.Fatalf("Invalid hash family [%s]", currentTestConfig.hashFamily)
		}

		h.Write(b)
		h2 := h.Sum(nil)
		if !bytes.Equal(h1, h2) {
			t.Fatalf("Discrempancy found in HASH result [%x], [%x]!=[%x]", b, h1, h2)
		}
	}
}

func TestAddWrapper(t *testing.T) {
	t.Parallel()
	p, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	gm, ok := p.(*CSP)
	assert.True(t, ok)

	tester := func(o interface{}, getter func(t reflect.Type) (interface{}, bool)) {
		tt := reflect.TypeOf(o)
		err := gm.AddWrapper(tt, o)
		assert.NoError(t, err)
		o2, ok := getter(tt)
		assert.True(t, ok)
		assert.Equal(t, o, o2)
	}

	tester(&mocks.KeyGenerator{}, func(t reflect.Type) (interface{}, bool) { o, ok := gm.KeyGenerators[t]; return o, ok })
	tester(&mocks.KeyDeriver{}, func(t reflect.Type) (interface{}, bool) { o, ok := gm.KeyDerivers[t]; return o, ok })
	tester(&mocks.KeyImporter{}, func(t reflect.Type) (interface{}, bool) { o, ok := gm.KeyImporters[t]; return o, ok })
	tester(&mocks.Encryptor{}, func(t reflect.Type) (interface{}, bool) { o, ok := gm.Encryptors[t]; return o, ok })
	tester(&mocks.Decryptor{}, func(t reflect.Type) (interface{}, bool) { o, ok := gm.Decryptors[t]; return o, ok })
	tester(&mocks.Signer{}, func(t reflect.Type) (interface{}, bool) { o, ok := gm.Signers[t]; return o, ok })
	tester(&mocks.Verifier{}, func(t reflect.Type) (interface{}, bool) { o, ok := gm.Verifiers[t]; return o, ok })
	tester(&mocks.Hasher{}, func(t reflect.Type) (interface{}, bool) { o, ok := gm.Hashers[t]; return o, ok })

	// Add invalid wrapper
	err := gm.AddWrapper(reflect.TypeOf(cleanup), cleanup)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "wrapper type not valid, must be on of: KeyGenerator, KeyDeriver, KeyImporter, Encryptor, Decryptor, Signer, Verifier, Hasher")
}
