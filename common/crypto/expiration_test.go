package crypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/11090815/hyperchain/common/crypto"
	"github.com/11090815/hyperchain/common/crypto/tlsgen"
	"github.com/11090815/hyperchain/protos-go/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func GenerateTestData(t *testing.T) {
	ca, err := tlsgen.NewCA()
	require.NoError(t, err)

	path, err := os.Getwd()
	require.NoError(t, err)

	path = filepath.Join(path, "testdata")
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		err = os.Mkdir(path, os.FileMode(0755))
		require.NoError(t, err)
	} else if err == nil {
		return
	}

	err = os.WriteFile(fmt.Sprintf("%s/%s", path, "goodcert.pem"), ca.CertBytes(), os.FileMode(0600))
	require.NoError(t, err)

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	badPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(1234),
		KeyUsage: x509.KeyUsageDigitalSignature,
		Subject: pkix.Name{
			SerialNumber: "1234",
		},
		NotAfter: time.Now().Add(time.Hour*(-24)),
	}

	raw, err := x509.CreateCertificate(rand.Reader, template, template, &badPrivateKey.PublicKey, signer)
	require.NoError(t, err)
	badCertPEM := pem.EncodeToMemory(&pem.Block{Type: "BAD CERTIFICATE", Bytes: raw})
	copy(badCertPEM[100:240], badCertPEM[101:241])
	err = os.WriteFile(fmt.Sprintf("%s/%s", path, "badcert.pem"), badCertPEM, os.FileMode(0600))
	require.NoError(t, err)
}

func TestX509CertExpiresAt(t *testing.T) {
	GenerateTestData(t)
	
	certPEM, err := os.ReadFile(filepath.Join("testdata", "goodcert.pem"))
	require.NoError(t, err)

	sID := &msp.SerializedIdentity{
		IdBytes: certPEM,
	}

	serializedSID, err := proto.Marshal(sID)
	require.NoError(t, err)

	expirationTime := crypto.ExpiresAt(serializedSID)
	require.NotEqual(t, expirationTime, time.Time{})
}

func TestX509InvalidCertExpiresAt(t *testing.T) {
	GenerateTestData(t)
	badCertPEM, err := os.ReadFile(filepath.Join("testdata", "badcert.pem"))
	require.NoError(t, err)

	sID := &msp.SerializedIdentity{
		IdBytes: badCertPEM,
	}

	serializedSID, err := proto.Marshal(sID)
	require.NoError(t, err)

	expirationTime := crypto.ExpiresAt(serializedSID)
	require.Equal(t, expirationTime, time.Time{})
}
