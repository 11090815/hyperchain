package msp_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/common/crypto/tlsgen"
	"github.com/stretchr/testify/require"
)

func pemToCert(t *testing.T, certPEM []byte) *x509.Certificate {
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	return cert
}

func TestCertificateVerifyOpts(t *testing.T) {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		// CurrentTime:   caCert.NotBefore.Add(time.Second),
	}

	ca, err := tlsgen.NewCA()
	require.NoError(t, err)
	caCert := pemToCert(t, ca.PublicKeyPEM())
	roots.AddCert(caCert)

	clientCertKP, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)
	clientCert := pemToCert(t, clientCertKP.PublicKeyPEM())

	// 由第一级 CA 生成的客户端证书，验证后得到的证书链只有一条，
	// 那一条证书链中第一个证书是客户端证书，第二个证书是 CA 证书
	chains, err := clientCert.Verify(opts)
	require.NoError(t, err)

	require.Equal(t, 1, len(chains))
	require.Equal(t, 2, len(chains[0]))
	require.True(t, chains[0][0].Equal(clientCert))
	require.True(t, chains[0][1].Equal(caCert))
	require.Nil(t, chains[0][0].CheckSignatureFrom(chains[0][1]))

	/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

	intermediateCA, err := ca.NewIntermediateCA()
	require.NoError(t, err)
	intermediateCACert := pemToCert(t, intermediateCA.PublicKeyPEM())
	intermediates.AddCert(intermediateCACert)

	intermediateCAServerCertKP, err := intermediateCA.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)
	intermediateCAServerCert := pemToCert(t, intermediateCAServerCertKP.PublicKeyPEM())

	// 由中级 CA 生成的服务端证书，验证后得到的证书链只有一条，
	// 那一条证书链中第一个证书是服务端证书，第二个证书是中级
	// CA 证书，第三个证书是一级 CA 证书。
	chains, err = intermediateCAServerCert.Verify(opts)
	require.NoError(t, err)

	require.Equal(t, 1, len(chains))
	require.Equal(t, 3, len(chains[0]))
	require.True(t, chains[0][0].Equal(intermediateCAServerCert))
	require.True(t, chains[0][1].Equal(intermediateCACert))
	require.True(t, chains[0][2].Equal(caCert))
	require.Nil(t, chains[0][0].CheckSignatureFrom(chains[0][1]))
	require.Nil(t, chains[0][1].CheckSignatureFrom(chains[0][2]))

	/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

	intermediate2CA, err := intermediateCA.NewIntermediateCA()
	require.NoError(t, err)
	intermediate2CACert := pemToCert(t, intermediate2CA.PublicKeyPEM())

	intermediate2CAServerCertKP, err := intermediate2CA.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)
	intermediate2CAServerCert := pemToCert(t, intermediate2CAServerCertKP.PublicKeyPEM())

	_, err = intermediate2CAServerCert.Verify(opts)
	require.ErrorContains(t, err, "x509: certificate signed by unknown authority")

	// 由 2 级中级 CA 生成的服务端证书，验证后得到的证书链只有一条，
	// 那一条证书链中第一个证书是服务端证书，第二个证书是 2 级中级
	// CA 证书，第三个证书是中级 CA 证书，第四个证书是一级 CA 证书。
	intermediates.AddCert(intermediate2CACert)
	chains, err = intermediate2CAServerCert.Verify(opts)
	require.NoError(t, err)

	require.Equal(t, 1, len(chains))
	require.Equal(t, 4, len(chains[0]))
	require.True(t, chains[0][0].Equal(intermediate2CAServerCert))
	require.True(t, chains[0][1].Equal(intermediate2CACert))
	require.True(t, chains[0][2].Equal(intermediateCACert))
	require.True(t, chains[0][3].Equal(caCert))
	require.Nil(t, chains[0][0].CheckSignatureFrom(chains[0][1]))
	require.Nil(t, chains[0][1].CheckSignatureFrom(chains[0][2]))
	require.Nil(t, chains[0][2].CheckSignatureFrom(chains[0][3]))
}

func TestKeyImport(t *testing.T) {
	certPath := filepath.Join("..", "internal", "pkg", "comm", "testdata", "certs", "nwpu-1-cert.pem")
	keyPath := filepath.Join("..", "internal", "pkg", "comm", "testdata", "certs", "nwpu-1-key.pem")

	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)

	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)

	certDER, _ := pem.Decode(certPEM)
	csp, err := bccsp.NewBCCSP(nil)
	require.NoError(t, err)

	keyDER, _ := pem.Decode(keyPEM)

	cert, err := x509.ParseCertificate(certDER.Bytes)
	require.NoError(t, err)

	publicKey, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)

	privateKey, err := csp.KeyImport(keyDER.Bytes, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: true})
	require.NoError(t, err)

	msg := []byte("hello")
	digest, err := csp.Hash(msg, &bccsp.SHA256Opts{})
	require.NoError(t, err)

	sig, err := csp.Sign(privateKey, digest, nil)
	require.NoError(t, err)

	valid, err := csp.Verify(publicKey, sig, digest, nil)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestIntermediateCertGetValidationChain(t *testing.T) {
	ca, err := tlsgen.NewCA()
	require.NoError(t, err)

	intermediateCertKP1, err := ca.NewIntermediateCA()
	require.NoError(t, err)

	intermediateCertKP2, err := intermediateCertKP1.NewIntermediateCA()
	require.NoError(t, err)

	intermediateCertKP3, err := intermediateCertKP2.NewIntermediateCA()
	require.NoError(t, err)

	intermediateCertKP4, err := intermediateCertKP3.NewIntermediateCA()
	require.NoError(t, err)

	icert4DER := intermediateCertKP4.PublicKeyDER()
	icert4, err := x509.ParseCertificate(icert4DER)
	require.NoError(t, err)

	opt := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	{
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(ca.PublicKeyPEM())

		intermediates := x509.NewCertPool()
		intermediates.AppendCertsFromPEM(intermediateCertKP1.PublicKeyPEM())
		intermediates.AppendCertsFromPEM(intermediateCertKP2.PublicKeyPEM())
		intermediates.AppendCertsFromPEM(intermediateCertKP3.PublicKeyPEM())

		opt.Roots = roots
		opt.Intermediates = intermediates
	}

	chain4, err := icert4.Verify(opt)
	require.NoError(t, err)
	t.Log(len(chain4[0]))

	chainCert0 := chain4[0][0]
	chainCert1 := chain4[0][1]
	chainCert2 := chain4[0][2]
	chainCert3 := chain4[0][3]
	chainCert4 := chain4[0][4]

	require.Equal(t, chainCert0.Raw, intermediateCertKP4.PublicKeyDER())
	require.Equal(t, chainCert1.Raw, intermediateCertKP3.PublicKeyDER())
	require.Equal(t, chainCert2.Raw, intermediateCertKP2.PublicKeyDER())
	require.Equal(t, chainCert3.Raw, intermediateCertKP1.PublicKeyDER())
	require.Equal(t, chainCert4.Raw, ca.PublicKeyDER())
}
