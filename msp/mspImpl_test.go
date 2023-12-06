package msp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/common/crypto/tlsgen"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
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

func genCert(t *testing.T, isExpired bool, isCA bool) []byte {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	// require.NoError(t, err)

	serialNum, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := x509.Certificate{
		Subject:      pkix.Name{SerialNumber: serialNum.String()},                  // 证书持有者的信息
		NotBefore:    time.Now().Add(time.Hour * (-48)),                            // 证书有效期开始时间不要早于一天前
		NotAfter:     time.Now().Add(time.Hour * 24),                               // 证书过期时间不要晚于一天后
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, // 定义了证书包含的密钥的用途：加密对称密钥 | 数字签名
		SerialNumber: serialNum,                                                    // 证书序列号，标识证书的唯一整数，重复的编号无法安装到系统里
	}

	if isExpired {
		template.NotAfter = time.Now().Add(time.Hour * (-24)) // 设置为一天前过期
	}

	if isCA {
		// 为证书颁发中心 CA 生成证书和密钥
		template.IsCA = true
		template.KeyUsage = template.KeyUsage | x509.KeyUsageCertSign | x509.KeyUsageCRLSign              // 用于校验公钥证书的签名 | 用于验证证书吊销列表的签名
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} // 建立TLS连接时进行客户端验证 | 建立TLS连接时进行服务器身份验证
		template.BasicConstraintsValid = true                                                             // 表示IsCA/MaxPathLen/MaxPathLenZero有效
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} // 非 CA 证书，建立 TLS 连接时，仅进行客户端验证
	}

	hash := sha256.New()
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	hash.Write(publicKeyBytes)
	template.SubjectKeyId = hash.Sum(nil)

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})

	return certPEM
}

func TestGenCert(t *testing.T) {
	_ = genCert(t, true, true)
}

func TestTLSCAValidation(t *testing.T) {
	niceCert := genCert(t, false, true)
	t.Run("nice cert", func(t *testing.T) {
		msp := &bccspmsp{
			opts: &x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			},
		}

		err := msp.setupTLSCAs(&pbmsp.HyperchainMSPConfig{
			TlsRootCerts: [][]byte{niceCert},
		})
		require.NoError(t, err)
	})

	expiredCert := genCert(t, true, true)
	t.Run("expired cert", func(t *testing.T) {
		msp := &bccspmsp{
			opts: &x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			},
		}

		err := msp.setupTLSCAs(&pbmsp.HyperchainMSPConfig{
			TlsRootCerts: [][]byte{expiredCert},
		})
		require.NoError(t, err)
	})

	nonCACert := genCert(t, false, false)
	t.Run("non ca cert", func(t *testing.T) {
		msp := &bccspmsp{
			opts: &x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			},
		}

		err := msp.setupTLSCAs(&pbmsp.HyperchainMSPConfig{
			TlsRootCerts: [][]byte{nonCACert},
		})
		require.Error(t, err)
	})

	t.Run("no ski cert", func(t *testing.T) {
		msp := &bccspmsp{
			opts: &x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			},
		}

		err := msp.setupTLSCAs(&pbmsp.HyperchainMSPConfig{
			TlsRootCerts: [][]byte{[]byte(caWithoutSKI)},
		})
		require.Error(t, err)
	})
}

func TestMalformedCertsChainSetup(t *testing.T) {
	ca, err := tlsgen.NewCA()
	require.NoError(t, err)

	inter, err := ca.NewIntermediateCA()
	require.NoError(t, err)

	ks, err := bccsp.NewFileBasedKeyStore("testdata", false)
	require.NoError(t, err)

	csp, err := bccsp.NewBCCSP(ks)
	require.NoError(t, err)

	// csp.GetHash(&bccsp.SHA256Opts{})
	msp := &bccspmsp{
		opts: &x509.VerifyOptions{
			Roots:         x509.NewCertPool(),
			Intermediates: x509.NewCertPool(),
		},
		csp: csp,
		cryptoConfig: &pbmsp.HyperchainCryptoConfig{
			HashAlgorithm: bccsp.SHA256,
		},
	}

	interCert, err := getCertFromPEM(inter.PublicKeyPEM())
	require.NoError(t, err)
	msp.opts.Roots.AddCert(interCert)
	msp.rootCerts = []Identity{&identity{cert: interCert}}
	err = msp.finalizeSetupCAs()
	require.NoError(t, err)

	_, _, err = msp.getIdentityFromConf(inter.PublicKeyPEM())
	require.NoError(t, err)
}

func TestCAValidation(t *testing.T) {
	niceCert := genCert(t, false, true)
	t.Run("nice cert", func(t *testing.T) {
		msp := &bccspmsp{
			opts: &x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			},
		}
		cert, err := getCertFromPEM(niceCert)
		require.NoError(t, err)

		msp.opts.Roots.AddCert(cert)
		msp.rootCerts = []Identity{&identity{cert: cert}}

		require.NoError(t, msp.finalizeSetupCAs())
	})

	nonCACert := genCert(t, false, false)
	t.Run("non ca cert", func(t *testing.T) {
		msp := &bccspmsp{
			opts: &x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			},
		}
		cert, err := getCertFromPEM(nonCACert)
		require.NoError(t, err)

		msp.opts.Roots.AddCert(cert)
		msp.rootCerts = []Identity{&identity{cert: cert}}

		require.Error(t, msp.finalizeSetupCAs())
	})

	t.Run("no ski cert", func(t *testing.T) {
		msp := &bccspmsp{
			opts: &x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			},
		}
		cert, err := getCertFromPEM([]byte(caWithoutSKI))
		require.NoError(t, err)

		msp.opts.Roots.AddCert(cert)
		msp.rootCerts = []Identity{&identity{cert: cert}}

		require.Error(t, msp.finalizeSetupCAs())
	})
}

var caWithoutSKI = `-----BEGIN CERTIFICATE-----
MIIDVjCCAj6gAwIBAgIJAKsK4xHz4yA2MA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQxFDASBgNVBAMMC2ZhYnJpYy50ZXN0MB4XDTE4MTExNTE5
MTA1MloXDTI5MTAyODE5MTA1MlowWzELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNv
bWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIG
A1UEAwwLZmFicmljLnRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDjpNeST0vgoT+MNTFiI6pB6cCXlF5drW+b3BVlGYtvRK7y6szSV+XH46kxyGt3
038tuVUOuPTyc40LxWQngGO8H5zwRYV5ELu57cfeLnI9MArOF4mUSQ5lkrG7zq4F
neDDSYWGfItetsNc75ut+HiN0KK6gZ1xMG7Op8mFCwlVvDCJ8tJjhltwta3ZbDIC
eLeNYtqvyZul+bNRIw883XXY1hBW8BW+tW0r0YTQPdXEwp/yEBkZhhkCmkt1l0tM
utfkxFsUM1kWqqG/NUuz7BqQ9FL59btXeYirD3+njLTERNdzDMEAn2aOgVwWAnye
KnOZ1P51T+YJAgTyQilf7py9AgMBAAGjHTAbMAwGA1UdEwQFMAMBAf8wCwYDVR0P
BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQCBtomvDwLqQh89IfjPpbwOduQDWyqp
BxGIlSNBaZkHR9WlnzRl13HZ4JklsaT/DRhKcnB5EuUHMHKUdPuhjx94F51WxlYc
f0wttSk8l5LfPAvLfL3/NwTT2YcyICA0glWF4D8FDUPKRTiOerR9KByrn4ktIjzd
vpx58pjg15TqKgrZF2h+TJ5jFa48O1wBvtMhP8WL6/6O+NjOEP56UnXPGie/3HLC
yvhEkMILRkzGUfd091cpuNxd+aGA37mZbwc+8UBpYbZFhq3NORL8zSxUQLzm1NcV
U98sznvJPRCkRiwYp5L9C5Xq72CHG/3M6cmoN0Cl0xjZicfpfnZSA/ix
-----END CERTIFICATE-----`
