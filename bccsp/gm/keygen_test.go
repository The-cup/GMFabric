/*
Copyright 2023 kasdect@163.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gm

import (
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"reflect"
	"testing"

	mocks2 "github.com/hyperledger/fabric/bccsp/mocks"
	"github.com/hyperledger/fabric/bccsp/sw/mocks"
	"github.com/stretchr/testify/assert"
)

func TestKeyGen(t *testing.T) {
	t.Parallel()

	expectedOpts := &mocks2.KeyGenOpts{EphemeralValue: true}
	expectetValue := &mocks2.MockKey{}
	expectedErr := errors.New("Expected Error")

	keyGenerators := make(map[reflect.Type]KeyGenerator)
	keyGenerators[reflect.TypeOf(&mocks2.KeyGenOpts{})] = &mocks.KeyGenerator{
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     expectedErr,
	}
	csp := CSP{KeyGenerators: keyGenerators}
	value, err := csp.KeyGen(expectedOpts)
	assert.Nil(t, value)
	assert.Contains(t, err.Error(), expectedErr.Error())

	keyGenerators = make(map[reflect.Type]KeyGenerator)
	keyGenerators[reflect.TypeOf(&mocks2.KeyGenOpts{})] = &mocks.KeyGenerator{
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     nil,
	}
	csp = CSP{KeyGenerators: keyGenerators}
	value, err = csp.KeyGen(expectedOpts)
	assert.Equal(t, expectetValue, value)
	assert.Nil(t, err)
}

func TestSM2KeyGenerator(t *testing.T) {
	t.Parallel()

	kg := &sm2KeyGenerator{}

	k, err := kg.KeyGen(nil)
	assert.NoError(t, err)

	sm2K, ok := k.(*sm2PrivateKey)
	assert.True(t, ok)
	assert.NotNil(t, sm2K.privKey)
	assert.Equal(t, sm2K.privKey.Curve, sm2.P256Sm2())
}

func TestSM4KeyGenerator(t *testing.T) {
	t.Parallel()

	kg := &sm4KeyGenerator{length: 32}

	k, err := kg.KeyGen(nil)
	assert.NoError(t, err)

	sm4K, ok := k.(*sm4PrivateKey)
	assert.True(t, ok)
	assert.NotNil(t, sm4K.privKey)
	assert.Equal(t, len(sm4K.privKey), 32)
}

func TestAESKeyGeneratorInvalidInputs(t *testing.T) {
	t.Parallel()

	kg := &sm4KeyGenerator{length: -1}

	_, err := kg.KeyGen(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Len must be larger than 0")
}
