package idemix

import (
	"fmt"
	"hash"
	"reflect"

	"errors"

	"github.com/11090815/hyperchain/bccsp"
)

// CSP provides a generic implementation of the BCCSP interface based
// on wrappers. It can be customized by providing implementations for the
// following algorithm-based wrappers: KeyGenerator, KeyDeriver, KeyImporter,
// Encryptor, Decryptor, Signer, Verifier, Hasher. Each wrapper is bound to a
// goland type representing either an option or a key.
type CSP struct {
	ks bccsp.KeyStore

	KeyGenerators map[reflect.Type]bccsp.KeyGenerator
	KeyDerivers   map[reflect.Type]bccsp.KeyDeriver
	KeyImporters  map[reflect.Type]bccsp.KeyImporter
	Encryptors    map[reflect.Type]bccsp.Encrypter
	Decryptors    map[reflect.Type]bccsp.Decrypter
	Signers       map[reflect.Type]bccsp.Signer
	Verifiers     map[reflect.Type]bccsp.Verifier
	Hashers       map[reflect.Type]bccsp.Hasher
}

func NewImpl(keyStore bccsp.KeyStore) (*CSP, error) {
	if keyStore == nil {
		return nil, errors.New("invalid bccsp.KeyStore instance, it must be different from nil")
	}

	encryptors := make(map[reflect.Type]bccsp.Encrypter)
	decryptors := make(map[reflect.Type]bccsp.Decrypter)
	signers := make(map[reflect.Type]bccsp.Signer)
	verifiers := make(map[reflect.Type]bccsp.Verifier)
	hashers := make(map[reflect.Type]bccsp.Hasher)
	keyGenerators := make(map[reflect.Type]bccsp.KeyGenerator)
	keyDerivers := make(map[reflect.Type]bccsp.KeyDeriver)
	keyImporters := make(map[reflect.Type]bccsp.KeyImporter)

	csp := &CSP{keyStore,
		keyGenerators, keyDerivers, keyImporters, encryptors,
		decryptors, signers, verifiers, hashers}

	return csp, nil
}

// KeyGen generates a key using opts.
func (csp *CSP) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("invalid Opts parameter, it must not be nil")
	}

	keyGenerator, found := csp.KeyGenerators[reflect.TypeOf(opts)]
	if !found {
		return nil, fmt.Errorf("unsupported 'KeyGenOpts' provided [%v]", opts)
	}

	k, err = keyGenerator.KeyGen(opts)
	if err != nil {
		return nil, fmt.Errorf("failed generating key with opts [%v]: [%s]", opts, err.Error())
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed storing key [%s]: [%s]", opts.Algorithm(), err.Error())
		}
	}

	return k, nil
}

// KeyDeriv derives a key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *CSP) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("invalid Key, it must not be nil")
	}
	if opts == nil {
		return nil, errors.New("invalid opts, it must not be nil")
	}

	keyDeriver, found := csp.KeyDerivers[reflect.TypeOf(k)]
	if !found {
		return nil, fmt.Errorf("unsupported 'Key' provided [%v]", k)
	}

	k, err = keyDeriver.KeyDeriv(k, opts)
	if err != nil {
		return nil, fmt.Errorf("failed deriving key with opts [%v]: [%s]", opts, err.Error())
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed storing key [%s]: [%s]", opts.Algorithm(), err.Error())
		}
	}

	return k, nil
}

// KeyImport imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *CSP) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("invalid raw, it must not be nil")
	}
	if opts == nil {
		return nil, errors.New("invalid opts, it must not be nil")
	}

	keyImporter, found := csp.KeyImporters[reflect.TypeOf(opts)]
	if !found {
		return nil, fmt.Errorf("unsupported 'KeyImportOpts' provided [%v]", opts)
	}

	k, err = keyImporter.KeyImport(raw, opts)
	if err != nil {
		return nil, fmt.Errorf("failed importing key with opts [%v]: [%s]", opts, err.Error())
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed storing imported key with opts [%v]: [%s]", opts, err.Error())
		}
	}

	return
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (csp *CSP) GetKey(ski []byte) (k bccsp.Key, err error) {
	k, err = csp.ks.GetKey(ski)
	if err != nil {
		return nil, fmt.Errorf("failed getting key for SKI [%v]: [%s]", ski, err.Error())
	}

	return
}

// Hash hashes messages msg using options opts.
func (csp *CSP) Hash(msg []byte, opts bccsp.HashOpts) (digest []byte, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("invalid opts, it must not be nil")
	}

	hasher, found := csp.Hashers[reflect.TypeOf(opts)]
	if !found {
		return nil, fmt.Errorf("unsupported 'HashOpt' provided [%v]", opts)
	}

	digest, err = hasher.Hash(msg, opts)
	if err != nil {
		return nil, fmt.Errorf("failed hashing with opts [%v]: [%s]", opts, err.Error())
	}

	return
}

// GetHash returns and instance of hash.Hash using options opts.
// If opts is nil then the default hash function is returned.
func (csp *CSP) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("invalid opts, it must not be nil")
	}

	hasher, found := csp.Hashers[reflect.TypeOf(opts)]
	if !found {
		return nil, fmt.Errorf("unsupported 'HashOpt' provided [%v]", opts)
	}

	h, err = hasher.GetHash(opts)
	if err != nil {
		return nil, fmt.Errorf("failed getting hash function with opts [%v]: [%s]", opts, err.Error())
	}

	return
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (csp *CSP) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("invalid Key, it must not be nil")
	}
	if len(digest) == 0 {
		return nil, errors.New("invalid digest, cannot be empty")
	}

	keyType := reflect.TypeOf(k)
	signer, found := csp.Signers[keyType]
	if !found {
		return nil, fmt.Errorf("unsupported 'SignKey' provided [%s]", keyType)
	}

	signature, err = signer.Sign(k, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("failed signing with opts [%v]: [%s]", opts, err.Error())
	}

	return
}

// Verify verifies signature against key k and digest
func (csp *CSP) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("invalid Key, it must not be nil")
	}
	if len(signature) == 0 {
		return false, errors.New("invalid signature, cannot be empty")
	}
	if len(digest) == 0 {
		return false, errors.New("invalid digest, cannot be empty")
	}

	verifier, found := csp.Verifiers[reflect.TypeOf(k)]
	if !found {
		return false, fmt.Errorf("unsupported 'VerifyKey' provided [%v]", k)
	}

	valid, err = verifier.Verify(k, signature, digest, opts)
	if err != nil {
		return false, fmt.Errorf("failed verifing with opts [%v]: [%s]", opts, err.Error())
	}

	return
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *CSP) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncryptOpts) ([]byte, error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("invalid Key, it must not be nil")
	}

	encryptor, found := csp.Encryptors[reflect.TypeOf(k)]
	if !found {
		return nil, fmt.Errorf("unsupported 'EncryptKey' provided [%v]", k)
	}

	return encryptor.Encrypt(k, plaintext, opts)
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *CSP) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecryptOpts) (plaintext []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("invalid Key, it must not be nil")
	}

	decryptor, found := csp.Decryptors[reflect.TypeOf(k)]
	if !found {
		return nil, fmt.Errorf("unsupported 'DecryptKey' provided [%v]", k)
	}

	plaintext, err = decryptor.Decrypt(k, ciphertext, opts)
	if err != nil {
		return nil, fmt.Errorf("failed decrypting with opts [%v]: [%s]", opts, err.Error())
	}

	return
}

// AddWrapper binds the passed type to the passed wrapper.
// Notice that that wrapper must be an instance of one of the following interfaces:
// KeyGenerator, KeyDeriver, KeyImporter, Encryptor, Decryptor, Signer, Verifier, Hasher.
func (csp *CSP) AddWrapper(t reflect.Type, w interface{}) error {
	if t == nil {
		return errors.New("type cannot be nil")
	}
	if w == nil {
		return errors.New("wrapper cannot be nil")
	}
	switch dt := w.(type) {
	case bccsp.KeyGenerator:
		csp.KeyGenerators[t] = dt
	case bccsp.KeyImporter:
		csp.KeyImporters[t] = dt
	case bccsp.KeyDeriver:
		csp.KeyDerivers[t] = dt
	case bccsp.Encrypter:
		csp.Encryptors[t] = dt
	case bccsp.Decrypter:
		csp.Decryptors[t] = dt
	case bccsp.Signer:
		csp.Signers[t] = dt
	case bccsp.Verifier:
		csp.Verifiers[t] = dt
	case bccsp.Hasher:
		csp.Hashers[t] = dt
	default:
		return errors.New("wrapper type not valid, must be on of: KeyGenerator, KeyDeriver, KeyImporter, Encryptor, Decryptor, Signer, Verifier, Hasher")
	}
	return nil
}
