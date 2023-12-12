package factory

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/pkg/errors"
)

const (
	GMBasedFactoryName = "GM"
)

type GMFactory struct{}

// Name returns the name of this factory
func (f *GMFactory) Name() string {
	return SoftwareBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *GMFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if config == nil || config.SwOpts == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	swOpts := config.SwOpts

	var ks bccsp.KeyStore
	switch {
	case swOpts.FileKeystore != nil:
		fks, err := sw.NewFileBasedKeyStore(nil, swOpts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to initialize software key store")
		}
		ks = fks
	case swOpts.InmemKeystore != nil:
		ks = sw.NewInMemoryKeyStore()
	default:
		// Default to ephemeral key store
		ks = sw.NewDummyKeyStore()
	}

	return sw.NewWithParams(swOpts.SecLevel, swOpts.HashFamily, ks)
}

// SwOpts contains options for the SWFactory
type GMOpts struct {
}
