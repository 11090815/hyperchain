package bccsp

import (
	"crypto"
	"crypto/x509"
	"errors"
	"io"
)

type cryptoSigner struct {
	csp BCCSP
	sk  Key
	pk  interface{}
}

func NewCryptoSigner(csp BCCSP, key Key) (crypto.Signer, error) {
	if csp == nil {
		return nil, errors.New("bccsp instance must be different from nil")
	}

	if key == nil {
		return nil, errors.New("must provide secret key")
	}

	if key.Symmetric() {
		return nil, errors.New("secret key must be asymmetric")
	}

	pub, err := key.PublicKey()
	if err != nil {
		return nil, err
	}

	pkBytes, err := pub.Bytes()
	if err != nil {
		return nil, err
	}

	pk, err := x509.ParsePKIXPublicKey(pkBytes)
	if err != nil {
		return nil, err
	}

	return &cryptoSigner{csp: csp, sk: key, pk: pk}, nil
}

func (c *cryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return c.csp.Sign(c.sk, digest, opts)
}

func (c *cryptoSigner) Public() crypto.PublicKey {
	return c.pk
}
