package handlers

import (
	"crypto/sha256"

	"errors"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/common/mathlib"
	"github.com/11090815/hyperchain/idemix/schemes/crypto"
)

// NymSecretKey contains the nym secret key
type NymSecretKey struct {
	// SKI of this key
	Ski []byte
	// Sk is the idemix reference to the nym secret
	Sk *mathlib.Zr
	// Pk is the idemix reference to the nym public part
	Pk *mathlib.G1
	// Exportable if true, sk can be exported via the Bytes function
	Exportable bool

	Translator crypto.Translator
}

func computeSKI(serialise func() []byte) []byte {
	raw := serialise()

	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func NewNymSecretKey(sk *mathlib.Zr, pk *mathlib.G1, translator crypto.Translator, exportable bool) (*NymSecretKey, error) {
	ski := computeSKI(sk.Bytes)
	return &NymSecretKey{Ski: ski, Sk: sk, Pk: pk, Exportable: exportable, Translator: translator}, nil
}

func (k *NymSecretKey) Bytes() ([]byte, error) {
	if k.Exportable {
		return k.Sk.Bytes(), nil
	}

	return nil, errors.New("not supported")
}

func (k *NymSecretKey) SKI() []byte {
	c := make([]byte, len(k.Ski))
	copy(c, k.Ski)
	return c
}

func (*NymSecretKey) Symmetric() bool {
	return false
}

func (*NymSecretKey) IsPrivate() bool {
	return true
}

func (k *NymSecretKey) PublicKey() (bccsp.Key, error) {
	ski := computeSKI(k.Pk.Bytes)
	return &nymPublicKey{ski: ski, pk: k.Pk, translator: k.Translator}, nil
}

type nymPublicKey struct {
	// SKI of this key
	ski []byte
	// pk is the idemix reference to the nym public part
	pk *mathlib.G1

	translator crypto.Translator
}

func NewNymPublicKey(pk *mathlib.G1, translator crypto.Translator) *nymPublicKey {
	return &nymPublicKey{pk: pk, translator: translator}
}

func (k *nymPublicKey) Bytes() ([]byte, error) {
	ecp := k.translator.G1ToProto(k.pk)
	return append(ecp.X, ecp.Y...), nil
}

func (k *nymPublicKey) SKI() []byte {
	return computeSKI(k.pk.Bytes)
}

func (*nymPublicKey) Symmetric() bool {
	return false
}

func (*nymPublicKey) IsPrivate() bool {
	return false
}

func (k *nymPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}

// NymKeyDerivation derives nyms
type NymKeyDerivation struct {
	// Exportable is a flag to allow an issuer secret key to be marked as Exportable.
	// If a secret key is marked as Exportable, its Bytes method will return the key's byte representation.
	Exportable bool
	// User implements the underlying cryptographic algorithms
	User User

	Translator crypto.Translator
}

func (kd *NymKeyDerivation) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	userSecretKey, ok := k.(*UserSecretKey)
	if !ok {
		return nil, errors.New("invalid key, expected *userSecretKey")
	}
	nymKeyDerivationOpts, ok := opts.(*bccsp.IdemixNymKeyDerivationOpts)
	if !ok {
		return nil, errors.New("invalid options, expected *IdemixNymKeyDerivationOpts")
	}
	if nymKeyDerivationOpts.IssuerPK == nil {
		return nil, errors.New("invalid options, missing issuer public key")
	}
	issuerPK, ok := nymKeyDerivationOpts.IssuerPK.(*issuerPublicKey)
	if !ok {
		return nil, errors.New("invalid options, expected IssuerPK as *issuerPublicKey")
	}

	Nym, RandNym, err := kd.User.MakeNym(userSecretKey.Sk, issuerPK.pk)
	if err != nil {
		return nil, err
	}

	return NewNymSecretKey(RandNym, Nym, kd.Translator, kd.Exportable)
}

// NymPublicKeyImporter imports nym public keys
type NymPublicKeyImporter struct {
	// User implements the underlying cryptographic algorithms
	User User

	Translator crypto.Translator
}

func (i *NymPublicKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	bytes, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("invalid raw, expected byte array")
	}

	if len(bytes) == 0 {
		return nil, errors.New("invalid raw, it must not be nil")
	}

	pk, err := i.User.NewPublicNymFromBytes(bytes)
	if err != nil {
		return nil, err
	}

	return &nymPublicKey{pk: pk, translator: i.Translator}, nil
}

// NymKeyImporter imports nym public keys
type NymKeyImporter struct {
	Exportable bool
	// User implements the underlying cryptographic algorithms
	User User

	Translator crypto.Translator
}

func (i *NymKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	bytes, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("invalid raw, expected byte array")
	}

	if len(bytes) == 0 {
		return nil, errors.New("invalid raw, it must not be nil")
	}

	pk, sk, err := i.User.NewNymFromBytes(bytes)
	if err != nil {
		return nil, err
	}

	return NewNymSecretKey(sk, pk, i.Translator, i.Exportable)
}
