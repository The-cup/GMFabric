package factory

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm"
	"github.com/pkg/errors"
)

const (
	GMBasedFactoryName = "GM"
)

type GMFactory struct{}

// Name returns the name of this factory
func (f *GMFactory) Name() string {
	return GMBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *GMFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if config == nil || config.GmOpts == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	gmOpts := config.GmOpts

	var ks bccsp.KeyStore
	switch {
	case gmOpts.FileKeystore != nil:
		fks, err := gm.NewFileBasedKeyStore(nil, gmOpts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to initialize software key store")
		}
		ks = fks
	case gmOpts.InmemKeystore != nil:
		ks = gm.NewInMemoryKeyStore()
	default:
		// Default to ephemeral key store
		ks = gm.NewDummyKeyStore()
	}

	return gm.NewWithParams(gmOpts.SecLevel, gmOpts.HashFamily, ks)
}

// GmOpts contains options for the GMFactory
type GmOpts struct {
	SecLevel      int                `mapstructure:"security" json:"security" yaml:"Security"`
	HashFamily    string             `mapstructure:"hash" json:"hash" yaml:"Hash"`
	FileKeystore  *FileKeystoreOpts  `mapstructure:"filekeystore,omitempty" json:"filekeystore,omitempty" yaml:"FileKeyStore"`
	DummyKeystore *DummyKeystoreOpts `mapstructure:"dummykeystore,omitempty" json:"dummykeystore,omitempty"`
	InmemKeystore *InmemKeystoreOpts `mapstructure:"inmemkeystore,omitempty" json:"inmemkeystore,omitempty"`
}
