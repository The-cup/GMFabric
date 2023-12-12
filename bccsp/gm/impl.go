package gm

import (
	"reflect"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/pkg/errors"
)

var (
	logger = flogging.MustGetLogger("bccsp_gm")
)

type CSP struct {
	ks bccsp.KeyStore

	KeyGenerators map[reflect.Type]KeyGenerator
	KeyDerivers   map[reflect.Type]KeyDeriver
	KeyImporters  map[reflect.Type]KeyImporter
	Encryptors    map[reflect.Type]Encryptor
	Decryptors    map[reflect.Type]Decryptor
	Signers       map[reflect.Type]Signer
	Verifiers     map[reflect.Type]Verifier
	Hashers       map[reflect.Type]Hasher
}

func New(keyStore bccsp.KeyStore) (*CSP, error) {
	if keyStore == nil {
		return nil, errors.Errorf("Invalid bccsp.KeyStore instance. It must be different from nil.")
	}

	encryptors := make(map[reflect.Type]Encryptor)
	decryptors := make(map[reflect.Type]Decryptor)
	signers := make(map[reflect.Type]Signer)
	verifiers := make(map[reflect.Type]Verifier)
	hashers := make(map[reflect.Type]Hasher)
	keyGenerators := make(map[reflect.Type]KeyGenerator)
	keyDerivers := make(map[reflect.Type]KeyDeriver)
	keyImporters := make(map[reflect.Type]KeyImporter)

	csp := &CSP{keyStore,
		keyGenerators, keyDerivers, keyImporters, encryptors,
		decryptors, signers, verifiers, hashers}

	return csp, nil
}

func (csp *CSP) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil.")
	}

	keyGenerator := &sm2KeyGenerator{}

	k, err = keyGenerator.KeyGen(opts)
	if err != nil {
		return nil, errors.New("Failed generating key with opts")
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing key [%s]", opts.Algorithm())
		}
	}

	return k, nil
}

func (csp *CSP) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	// TODO: complete the function
	switch k.(type) {

	}

	return nil, errors.New("KeyDeriv not impl")
}

func (csp *CSP) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	k, err = keyImporter.KeyImport(raw, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed importing key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing imported key with opts [%v]", opts)
		}
	}
	return nil, errors.New("KeyDeriv not impl")
}

func (csp *CSP) GetKey(ski []byte) (k bccsp.Key, err error) {
	return nil, errors.New("KeyDeriv not impl")
}

func (csp *CSP) Hash(msg []byte, opts bccsp.HashOpts) (digest []byte, err error) {
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	hasher := &hasher{}
	digest, err = hasher.Hash(msg, opts)
	if err != nil {
		return nil, errors.New("Failed hashing with opts")
	}

	return
}

// AddWrapper binds the passed type to the passed wrapper.
// Notice that that wrapper must be an instance of one of the following interfaces:
// KeyGenerator, KeyDeriver, KeyImporter, Encryptor, Decryptor, Signer, Verifier, Hasher.
func (csp *CSP) AddWrapper(t reflect.Type, w interface{}) error {
	if t == nil {
		return errors.Errorf("type cannot be nil")
	}
	if w == nil {
		return errors.Errorf("wrapper cannot be nil")
	}
	switch dt := w.(type) {
	case KeyGenerator:
		csp.KeyGenerators[t] = dt
	case KeyImporter:
		csp.KeyImporters[t] = dt
	case KeyDeriver:
		csp.KeyDerivers[t] = dt
	case Encryptor:
		csp.Encryptors[t] = dt
	case Decryptor:
		csp.Decryptors[t] = dt
	case Signer:
		csp.Signers[t] = dt
	case Verifier:
		csp.Verifiers[t] = dt
	case Hasher:
		csp.Hashers[t] = dt
	default:
		return errors.Errorf("wrapper type not valid, must be on of: KeyGenerator, KeyDeriver, KeyImporter, Encryptor, Decryptor, Signer, Verifier, Hasher")
	}
	return nil
}
