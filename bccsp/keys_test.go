package bccsp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOriginPrivateKeyToPEM(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pemBytes, err := privateKeyToPEM(privateKey)
	require.NoError(t, err)

	get, err := pemToPrivateKey(pemBytes)
	require.NoError(t, err)

	switch key := get.(type) {
	case *ecdsa.PrivateKey:
		require.Equal(t, key.D.Bytes(), privateKey.D.Bytes())
		require.Equal(t, key.X.Bytes(), privateKey.X.Bytes())
		require.Equal(t, key.Y.Bytes(), privateKey.Y.Bytes())
		require.Equal(t, key.Curve.Params().B.Bytes(), privateKey.Curve.Params().B.Bytes())
		require.Equal(t, key.Curve.Params().BitSize, privateKey.Curve.Params().BitSize)
		require.Equal(t, key.Curve.Params().Gx.Bytes(), privateKey.Curve.Params().Gx.Bytes())
		require.Equal(t, key.Curve.Params().Gy.Bytes(), privateKey.Curve.Params().Gy.Bytes())
		require.Equal(t, key.Curve.Params().N.Bytes(), privateKey.Curve.Params().N.Bytes())
		require.Equal(t, key.Curve.Params().Name, privateKey.Curve.Params().Name)
		require.Equal(t, key.Curve.Params().P.Bytes(), privateKey.Curve.Params().P.Bytes())
	default:
		t.Fatalf("want *ecdsa.PrivateKey, but got %T", key)
	}
}

func TestMSP(t *testing.T) {
	csp, err := NewBCCSP(nil)
	require.NoError(t, err)

	rawKey, err := os.ReadFile("../msp/testdata/tls/keystore/key.pem")
	require.NoError(t, err)
	block, _ := pem.Decode(rawKey)
	key, err := csp.KeyImport(block.Bytes, &ECDSAPrivateKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	ski := key.SKI()

	rawCert, err := os.ReadFile("../msp/testdata/tls/signcerts/cert.pem")
	require.NoError(t, err)
	block, _ = pem.Decode(rawCert)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	publicKey, err := csp.KeyImport(cert, &X509PublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)

	require.True(t, bytes.Equal(ski, publicKey.SKI()))
}
