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
