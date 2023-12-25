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
	"crypto/rand"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidStore(t *testing.T) {
	t.Parallel()

	ks := NewInMemoryKeyStore()

	err := ks.StoreKey(nil)
	assert.EqualError(t, err, "key is nil")
}

func TestInvalidLoad(t *testing.T) {
	t.Parallel()

	ks := NewInMemoryKeyStore()

	_, err := ks.GetKey(nil)
	assert.EqualError(t, err, "ski is nil or empty")
}

func TestNoKeyFound(t *testing.T) {
	t.Parallel()

	ks := NewInMemoryKeyStore()

	ski := []byte("foo")
	_, err := ks.GetKey(ski)
	assert.EqualError(t, err, fmt.Sprintf("no key found for ski %x", ski))
}

func TestStoreLoad(t *testing.T) {
	t.Parallel()

	ks := NewInMemoryKeyStore()

	// generate a key for the keystore to find
	privKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	cspKey := &sm2PrivateKey{privKey}

	// store key
	err = ks.StoreKey(cspKey)
	assert.NoError(t, err)

	// load key
	key, err := ks.GetKey(cspKey.SKI())
	assert.NoError(t, err)

	assert.Equal(t, cspKey, key)
}

func TestReadOnly(t *testing.T) {
	t.Parallel()
	ks := NewInMemoryKeyStore()
	readonly := ks.ReadOnly()
	assert.Equal(t, false, readonly)
}

func TestStoreExisting(t *testing.T) {
	t.Parallel()

	ks := NewInMemoryKeyStore()

	// generate a key for the keystore to find
	privKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	cspKey := &sm2PrivateKey{privKey}

	// store key
	err = ks.StoreKey(cspKey)
	assert.NoError(t, err)

	// store key a second time
	err = ks.StoreKey(cspKey)
	assert.EqualError(t, err, fmt.Sprintf("ski %x already exists in the keystore", cspKey.SKI()))
}
