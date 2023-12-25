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
	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm2"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestInvalidStoreKey(t *testing.T) {
	t.Parallel()

	tempDir, err := ioutil.TempDir("", "bccspks")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	ks, err := NewFileBasedKeyStore(nil, filepath.Join(tempDir, "bccspks"), false)
	if err != nil {
		t.Fatalf("Failed initiliazing KeyStore [%s]", err)
	}

	err = ks.StoreKey(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm2PrivateKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm2PublicKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm4PrivateKey{nil, false})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm4PrivateKey{nil, true})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
}

func TestBigKeyFile(t *testing.T) {
	ksPath, err := ioutil.TempDir("", "bccspks")
	assert.NoError(t, err)
	defer os.RemoveAll(ksPath)

	ks, err := NewFileBasedKeyStore(nil, ksPath, false)
	assert.NoError(t, err)

	// Generate a key for keystore to find
	privKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	cspKey := &sm2PrivateKey{privKey}
	ski := cspKey.SKI()
	rawKey, err := privateKeyToPEM(privKey, nil)
	assert.NoError(t, err)

	// Large padding array, of some values PEM parser will NOOP
	bigBuff := make([]byte, 1<<17)
	for i := range bigBuff {
		bigBuff[i] = '\n'
	}
	copy(bigBuff, rawKey)

	//>64k, so that total file size will be too big
	ioutil.WriteFile(filepath.Join(ksPath, "bigfile.pem"), bigBuff, 0666)

	_, err = ks.GetKey(ski)
	assert.Error(t, err)
	expected := fmt.Sprintf("key with SKI %x not found in %s", ski, ksPath)
	assert.EqualError(t, err, expected)

	// 1k, so that the key would be found
	ioutil.WriteFile(filepath.Join(ksPath, "smallerfile.pem"), bigBuff[0:1<<10], 0666)

	_, err = ks.GetKey(ski)
	assert.NoError(t, err)
}

func TestReInitKeyStore(t *testing.T) {
	ksPath, err := ioutil.TempDir("", "bccspks")
	assert.NoError(t, err)
	defer os.RemoveAll(ksPath)

	ks, err := NewFileBasedKeyStore(nil, ksPath, false)
	assert.NoError(t, err)
	fbKs, isFileBased := ks.(*fileBasedKeyStore)
	assert.True(t, isFileBased)
	err = fbKs.Init(nil, ksPath, false)
	assert.EqualError(t, err, "keystore is already initialized")
}

func TestDirExists(t *testing.T) {
	r, err := dirExists("")
	assert.False(t, r)
	assert.NoError(t, err)

	r, err = dirExists(os.TempDir())
	assert.NoError(t, err)
	assert.Equal(t, true, r)

	r, err = dirExists(filepath.Join(os.TempDir(), "7rhf90239vhev90"))
	assert.NoError(t, err)
	assert.Equal(t, false, r)
}

func TestDirEmpty(t *testing.T) {
	_, err := dirEmpty("")
	assert.Error(t, err)

	path := filepath.Join(os.TempDir(), "7rhf90239vhev90")
	defer os.Remove(path)
	os.Mkdir(path, os.ModePerm)

	r, err := dirEmpty(path)
	assert.NoError(t, err)
	assert.Equal(t, true, r)

	r, err = dirEmpty(os.TempDir())
	assert.NoError(t, err)
	assert.Equal(t, false, r)
}