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

package factory

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGMFactoryName(t *testing.T) {
	f := &GMFactory{}
	assert.Equal(t, f.Name(), GMBasedFactoryName)
}

func TestGMFactoryGetInvalidArgs(t *testing.T) {
	f := &GMFactory{}

	_, err := f.Get(nil)
	assert.Error(t, err, "Invalid config. It must not be nil.")

	_, err = f.Get(&FactoryOpts{})
	assert.Error(t, err, "Invalid config. It must not be nil.")

	opts := &FactoryOpts{
		GmOpts: &GmOpts{},
	}
	_, err = f.Get(opts)
	assert.Error(t, err, "CSP:500 - Failed initializing configuration at [0,]")
}

func TestGMFactoryGet(t *testing.T) {
	f := &GMFactory{}

	opts := &FactoryOpts{
		GmOpts: &GmOpts{
			SecLevel:   -1,
			HashFamily: "SM",
		},
	}
	csp, err := f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)

	opts = &FactoryOpts{
		GmOpts: &GmOpts{
			SecLevel:     -1,
			HashFamily:   "SM",
			FileKeystore: &FileKeystoreOpts{KeyStorePath: os.TempDir()},
		},
	}
	csp, err = f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)

}
