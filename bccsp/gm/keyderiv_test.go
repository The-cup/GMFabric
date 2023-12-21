package gm

import (
	"errors"
	"reflect"
	"testing"

	mocks2 "github.com/hyperledger/fabric/bccsp/mocks"
	"github.com/hyperledger/fabric/bccsp/sw/mocks"
	"github.com/stretchr/testify/assert"
)

func TestKeyDeriv(t *testing.T) {
	t.Parallel()

	expectedKey := &mocks2.MockKey{BytesValue: []byte{1, 2, 3}}
	expectedOpts := &mocks2.KeyDerivOpts{EphemeralValue: true}
	expectetValue := &mocks2.MockKey{BytesValue: []byte{1, 2, 3, 4, 5}}
	expectedErr := errors.New("Expected Error")

	keyDerivers := make(map[reflect.Type]KeyDeriver)
	keyDerivers[reflect.TypeOf(&mocks2.MockKey{})] = &mocks.KeyDeriver{
		KeyArg:  expectedKey,
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     expectedErr,
	}
	csp := CSP{KeyDerivers: keyDerivers}
	value, err := csp.KeyDeriv(expectedKey, expectedOpts)
	assert.Nil(t, value)
	assert.Contains(t, err.Error(), expectedErr.Error())

	keyDerivers = make(map[reflect.Type]KeyDeriver)
	keyDerivers[reflect.TypeOf(&mocks2.MockKey{})] = &mocks.KeyDeriver{
		KeyArg:  expectedKey,
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     nil,
	}
	csp = CSP{KeyDerivers: keyDerivers}
	value, err = csp.KeyDeriv(expectedKey, expectedOpts)
	assert.Equal(t, expectetValue, value)
	assert.Nil(t, err)
}

func TestSM2PublicKeyKeyDeriver(t *testing.T) {
	t.Parallel()

	kd := sm2PublicKeyKeyDeriver{}

	_, err := kd.KeyDeriv(&mocks2.MockKey{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid opts parameter. It must not be nil.")

	_, err = kd.KeyDeriv(&sm2PublicKey{}, &mocks2.KeyDerivOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported 'KeyDerivOpts' provided [")
}

func TestSM2PrivateKeyKeyDeriver(t *testing.T) {
	t.Parallel()

	kd := sm2PrivateKeyKeyDeriver{}

	_, err := kd.KeyDeriv(&mocks2.MockKey{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid opts parameter. It must not be nil.")

	_, err = kd.KeyDeriv(&sm2PrivateKey{}, &mocks2.KeyDerivOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported 'KeyDerivOpts' provided [")
}

func TestSM4PrivateKeyKeyDeriver(t *testing.T) {
	t.Parallel()

	kd := sm4PrivateKeyKeyDeriver{}

	_, err := kd.KeyDeriv(&mocks2.MockKey{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid opts parameter. It must not be nil.")

	_, err = kd.KeyDeriv(&sm4PrivateKey{}, &mocks2.KeyDerivOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported 'KeyDerivOpts' provided [")
}
