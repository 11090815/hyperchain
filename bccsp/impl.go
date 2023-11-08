package bccsp

import (
	"errors"
	"fmt"
	"hash"
	"reflect"
)

type CSP struct {
	ks KeyStore

	KeyGenerators map[reflect.Type]KeyGenerator
	KeyDerivers   map[reflect.Type]KeyDeriver
	KeyImporters  map[reflect.Type]KeyImporter
	Encrypters    map[reflect.Type]Encrypter
	Decrypters    map[reflect.Type]Decrypter
	Signers       map[reflect.Type]Signer
	Verifiers     map[reflect.Type]Verifier
	Hashers       map[reflect.Type]Hasher
}

func NewCSP(keyStore KeyStore) (*CSP, error) {
	if keyStore == nil {
		return nil, errors.New("if you want to new a crypto service provider, you should provide a non-nil key store")
	}

	return &CSP{
		ks:            keyStore,
		KeyGenerators: make(map[reflect.Type]KeyGenerator),
		KeyDerivers:   make(map[reflect.Type]KeyDeriver),
		KeyImporters:  make(map[reflect.Type]KeyImporter),
		Encrypters:    make(map[reflect.Type]Encrypter),
		Decrypters:    make(map[reflect.Type]Decrypter),
		Signers:       make(map[reflect.Type]Signer),
		Verifiers:     make(map[reflect.Type]Verifier),
		Hashers:       make(map[reflect.Type]Hasher),
	}, nil
}

func (csp *CSP) GetKey(ski []byte) (key Key, err error) {
	return csp.ks.GetKey(ski)
}

func (csp *CSP) KeyGen(opts KeyGenOpts) (key Key, err error) {
	if opts == nil {
		return nil, errors.New("if you want to generate a key, you should provide a non-nil option")
	}

	generator, found := csp.KeyGenerators[reflect.TypeOf(opts)]
	if !found {
		return nil, fmt.Errorf("no key generator for option [%T]", opts)
	}

	key, err = generator.KeyGen(opts)
	if err != nil {
		return nil, err
	}

	if !opts.Ephemeral() {
		return key, csp.ks.StoreKey(key)
	}

	return key, nil
}

func (csp *CSP) KeyDeriv(key Key, opts KeyDerivOpts) (dkey Key, err error) {
	if opts == nil {
		return nil, errors.New("if you want to deriv a key, you should provide a non-nil option")
	}

	if key == nil {
		return nil, errors.New("if you want to deriv a key, you should provide a non-nil key")
	}

	deriver, found := csp.KeyDerivers[reflect.TypeOf(key)]
	if !found {
		return nil, fmt.Errorf("no key deriver for key [%T]", key)
	}

	key, err = deriver.KeyDeriv(key, opts)
	if err != nil {
		return nil, err
	}

	if !opts.Ephemeral() {
		return key, csp.ks.StoreKey(key)
	}

	return key, nil
}

func (csp *CSP) KeyImport(raw interface{}, opts KeyImportOpts) (key Key, err error) {
	if opts == nil {
		return nil, errors.New("if you want to import a key, you should provide non-nil option")
	}

	// 根据选项的种类选择密钥导入器。
	importer, found := csp.KeyImporters[reflect.TypeOf(opts)]
	if !found {
		return nil, fmt.Errorf("no importer for option [%T]", opts)
	}
	key, err = importer.KeyImport(raw, opts)
	if err != nil {
		return nil, err
	}

	if !opts.Ephemeral() {
		return key, csp.ks.StoreKey(key)
	}

	return key, nil
}

func (csp *CSP) Hash(msg []byte, opts HashOpts) (digest []byte, err error) {
	if opts == nil {
		return nil, errors.New("if you want to get the digest of some message, you should provide a non-nil option")
	}

	// 根据选项的种类选择 hasher。
	hasher, found := csp.Hashers[reflect.TypeOf(opts)]
	if !found {
		return nil, fmt.Errorf("no hasher for option [%T]", opts)
	}

	return hasher.Hash(msg, opts)
}

func (csp *CSP) GetHash(opts HashOpts) (h hash.Hash, err error) {
	if opts == nil {
		return nil, errors.New("if you want to get a hash function, you should provide a non-nil option")
	}

	// 根据选项的种类选择 hasher。
	hasher, found := csp.Hashers[reflect.TypeOf(opts)]
	if !found {
		return nil, fmt.Errorf("no hasher for option [%T]", opts)
	}

	return hasher.GetHash(opts)
}

func (csp *CSP) Sign(key Key, digest []byte, opts SignerOpts) (signature []byte, err error) {
	if key == nil {
		return nil, fmt.Errorf("if you want to sign the digest of some message, you should provide a key")
	}

	// 根据密钥的种类选择签名算法。
	signer, found := csp.Signers[reflect.TypeOf(key)]
	if !found {
		return nil, fmt.Errorf("no signer for key [%T]", key)
	}

	return signer.Sign(key, digest, opts)
}

func (csp *CSP) Verify(key Key, signature, digest []byte, opts SignerOpts) (valid bool, err error) {
	if key == nil {
		return false, fmt.Errorf("if you want to verify the signature, you should provide a key")
	}

	// 根据密钥的种类选择验证器。
	verifier, found := csp.Verifiers[reflect.TypeOf(key)]
	if !found {
		return false, fmt.Errorf("no verifier for key [%T]", key)
	}

	return verifier.Verify(key, signature, digest, opts)
}

func (csp *CSP) Encrypt(key Key, plaintext []byte, opts EncryptOpts) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("if you want to encrypt plaintext, you should provide a key")
	}

	// 根据密钥的种类选择加密器。
	encrypter, ok := csp.Encrypters[reflect.TypeOf(key)]
	if !ok {
		return nil, fmt.Errorf("no encrypter for key [%T]", key)
	}

	return encrypter.Encrypt(key, plaintext, opts)
}

func (csp *CSP) Decrypt(key Key, ciphertext []byte, opts DecryptOpts) (plaintext []byte, err error) {
	if key == nil {
		return nil, fmt.Errorf("if you want to decrypt ciphertext, you should provide a key")
	}

	decrypter, found := csp.Decrypters[reflect.TypeOf(key)]
	if !found {
		return nil, fmt.Errorf("no decrypter for key [%T]", key)
	}

	// 根据密钥种类选择解密器。
	if plaintext, err = decrypter.Decrypt(key, ciphertext, opts); err != nil {
		return nil, fmt.Errorf("failed decrypting ciphertext: [%s]", err.Error())
	}

	return plaintext, nil
}

// AddWrapper 重新注册 KeyGenerator KeyImporter KeyDeriver Encrypter Decrypter Signer Verifier Hasher。
func (csp *CSP) AddWrapper(typ reflect.Type, wrapper interface{}) error {
	if typ == nil {
		return errors.New("the given type shouldn't be nil")
	}
	if wrapper == nil {
		return errors.New("the given wrapper shouldn't be nil")
	}

	switch wrapperType := wrapper.(type) {
	case KeyGenerator:
		csp.KeyGenerators[typ] = wrapperType
	case KeyImporter:
		csp.KeyImporters[typ] = wrapperType
	case KeyDeriver:
		csp.KeyDerivers[typ] = wrapperType
	case Encrypter:
		csp.Encrypters[typ] = wrapperType
	case Decrypter:
		csp.Decrypters[typ] = wrapperType
	case Signer:
		csp.Signers[typ] = wrapperType
	case Verifier:
		csp.Verifiers[typ] = wrapperType
	case Hasher:
		csp.Hashers[typ] = wrapperType
	default:
		return fmt.Errorf("invalid wrapper, want [KeyGenerator KeyImporter KeyDeriver Encrypter Decrypter Signer Verifier Hasher], but got [%T]", wrapper)
	}
	return nil
}
