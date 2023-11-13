package bccsp

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
)

type KeyImporter interface {
	KeyImport(raw interface{}, opts KeyImportOpts) (Key, error)
}

type aesKeyImporter struct{}

func (*aesKeyImporter) KeyImport(raw interface{}, opts KeyImportOpts) (Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid aes key type, want bytes, but got [%T]", raw)
	}

	if len(aesRaw) == 0 {
		return nil, errors.New("invalid aes key: [the content is empty]")
	}

	if len(aesRaw) != 32 {
		return nil, fmt.Errorf("invalid aes key: [the length of the key should be 32, but got %d]", len(aesRaw))
	}

	return &aesKey{key: aesRaw, exportable: false}, nil
}

type ecdsaPKIXPublicKeyImporter struct{}

func (*ecdsaPKIXPublicKeyImporter) KeyImport(raw interface{}, opts KeyImportOpts) (Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid ecdsa public key material, want bytes, but got [%T]", raw)
	}

	if len(der) == 0 {
		return nil, errors.New("invalid ecdsa public key material: [the content is empty]")
	}

	key, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed converting pkix to ecdsa public key: [%s]", err.Error())
	}

	ecdsaPK, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed casting to *ecdsa.PublicKey")
	}

	return &ecdsaPublicKey{publicKey: ecdsaPK}, nil
}

type ecdsaPrivateKeyImporter struct{}

func (*ecdsaPrivateKeyImporter) KeyImport(raw interface{}, opts KeyImportOpts) (Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid ecdsa private key material, want bytes, but got [%T]", raw)
	}

	if len(der) == 0 {
		return nil, errors.New("invalid ecdsa private key material: [the content is empty]")
	}

	key, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed converting to ecdsa private key:[ %s]", err.Error())
	}

	ecdsaSK, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed casting to *ecdsa.PrivateKey")
	}

	return &ecdsaPrivateKey{privateKey: ecdsaSK}, nil
}

// type ecdsaGoPublicKeyImporter struct{}

// func (*ecdsaGoPublicKeyImporter) KeyImport(raw interface{}, opts KeyImportOpts) (Key, error) {
// 	key, ok := raw.(*ecdsa.PublicKey)
// 	if !ok {
// 		return nil, fmt.Errorf("invalid go ecdsa public key material, want *ecdsa.PublicKey, but got [%T]", raw)
// 	}

// 	return &ecdsaPublicKey{publicKey: key}, nil
// }

type x509PublicKeyImporter struct {
	csp *CSP
}

func (ki *x509PublicKeyImporter) KeyImport(raw interface{}, opts KeyImportOpts) (Key, error) {
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, fmt.Errorf("invalid x509 public key material, want *x509.Certificate, but got [%T]", raw)
	}

	pk := x509Cert.PublicKey

	switch pk := pk.(type) {
	case *ecdsa.PublicKey:
		return &ecdsaPublicKey{publicKey: pk}, nil
	default:
		return nil, fmt.Errorf("x509 certificate public key type not recognized, only support *ecdsa.PublicKey, but got [%T]", pk)
	}
}
