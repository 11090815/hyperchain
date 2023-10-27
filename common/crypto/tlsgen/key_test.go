package tlsgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateCertificate(t *testing.T) {
	template, err := newCertTemplate()
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	publicKeyDERPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})

	block, _ := pem.Decode(publicKeyDERPEM)

	require.Equal(t, block.Bytes, raw)
}

func TestSignDifferentFromParent(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	template, err := newCertTemplate()
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = x509.CreateCertificate(rand.Reader, &template, ca.tlsCert, &privateKey.PublicKey, privateKey)
	require.Contains(t, err.Error(), "x509: provided PrivateKey doesn't match parent's PublicKey")
}
