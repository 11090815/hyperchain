package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func test(f func() error) error {
	return f()
}

func TestReturnOrder(t *testing.T) {
	variable := ""
	f := func() error {
		variable = "hello, world"
		return nil
	}

	val, err := variable, test(f)

	fmt.Println(val)
	fmt.Println(err)
}

func TestNewCA(t *testing.T) {
	path := t.TempDir()
	ca, err := NewCA(path, "org1", "university1", "china", "anhui", "hefei", "", "", "230000")
	require.NoError(t, err)
	_ = ca
}

func TestLoadECDSACertificateAndUse(t *testing.T) {
	path := t.TempDir()
	ca, err := NewCA(path, "org1", "university1", "china", "anhui", "hefei", "", "", "230000")
	require.NoError(t, err)

	cert, err := LoadECDSACertificate(path)
	require.NoError(t, err)

	require.Equal(t, ca.SignCert, cert)
}

func TestSignCertificate(t *testing.T) {
	path := t.TempDir()
	ca, err := NewCA(path, "org1", "university1", "china", "anhui", "hefei", "", "", "230000")
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	path2 := t.TempDir()
	signedCert, err := ca.SignCertificate(path2, "signedCert", nil, nil, &privateKey.PublicKey, 0, nil)
	require.NoError(t, err)

	loadedCert, err := LoadECDSACertificate(path2)
	require.NoError(t, err)
	require.Equal(t, signedCert, loadedCert)
}
