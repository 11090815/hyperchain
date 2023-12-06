package msp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/core/config/configtest"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

var notACert = `-----BEGIN X509 CRL-----
MIIBYzCCAQgCAQEwCgYIKoZIzj0EAwIwfzELMAkGA1UEBhMCVVMxEzARBgNVBAgT
CkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xHzAdBgNVBAoTFklu
dGVybmV0IFdpZGdldHMsIEluYy4xDDAKBgNVBAsTA1dXVzEUMBIGA1UEAxMLZXhh
bXBsZS5jb20XDTE3MDEyMzIwNTYyMFoXDTE3MDEyNjIwNTYyMFowJzAlAhQERXCx
LHROap1vM3CV40EHOghPTBcNMTcwMTIzMjA0NzMxWqAvMC0wHwYDVR0jBBgwFoAU
F2dCPaqegj/ExR2fW8OZ0bWcSBAwCgYDVR0UBAMCAQgwCgYIKoZIzj0EAwIDSQAw
RgIhAOTTpQYkGO+gwVe1LQOcNMD5fzFViOwBUraMrk6dRMlmAiEA8z2dpXKGwHrj
FRBbKkDnSpaVcZgjns+mLdHV2JkF0gk=
-----END X509 CRL-----`

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

func TestMain(m *testing.M) {
	var err error
	mspDir := configtest.GetDevMspDir()
	conf, err = GetLocalMSPConfig(mspDir, "SampleOrg")
	if err != nil {
		log.Fatal(err)
	}

	ks, err := bccsp.NewFileBasedKeyStore("", true)
	if err != nil {
		log.Fatal(err)
	}
	csp, err := bccsp.NewBCCSP(ks)
	if err != nil {
		log.Fatal(err)
	}
	msp = newBCCSPMSP(csp)

	err = msp.Setup(conf)
	if err != nil {
		log.Fatal(err)
	}

	ret := m.Run()
	os.Exit(ret)
}

func TestMSPParsers(t *testing.T) {
	_, _, err := msp.(*bccspmsp).getIdentityFromConf(nil)
	require.Error(t, err)
	_, _, err = msp.(*bccspmsp).getIdentityFromConf([]byte{1, 2, 3})
	require.Error(t, err)
	_, _, err = msp.(*bccspmsp).getIdentityFromConf([]byte(notACert))
	require.Error(t, err)

	_, err = msp.(*bccspmsp).getSigningIdentityFromConf(nil)
	require.Error(t, err)

	sigid := &pbmsp.SigningIdentityInfo{PublicSigner: []byte("bad"), PrivateSigner: nil}
	_, err = msp.(*bccspmsp).getSigningIdentityFromConf(sigid)
	require.Error(t, err)

	ki := &pbmsp.KeyInfo{KeyIdentifier: "peer", KeyMaterial: nil}
	sigid = &pbmsp.SigningIdentityInfo{PublicSigner: []byte("bad"), PrivateSigner: ki}
	_, err = msp.(*bccspmsp).getSigningIdentityFromConf(sigid)
	require.Error(t, err)
}

func TestGetSigningIdentityFromConfWithWrongPrivateCert(t *testing.T) {
	oldRoots := msp.(*bccspmsp).opts.Roots
	defer func() {
		msp.(*bccspmsp).opts.Roots = oldRoots
	}()

	_, cert := generateSelfSignedCert(t, time.Now())
	msp.(*bccspmsp).opts.Roots = x509.NewCertPool()
	msp.(*bccspmsp).opts.Roots.AddCert(cert)

	rawPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	ki := &pbmsp.KeyInfo{
		KeyIdentifier: "wrong encoding",
		KeyMaterial:   []byte("xxxx"),
	}
	sigid := &pbmsp.SigningIdentityInfo{PublicSigner: rawPEM, PrivateSigner: ki}
	_, err := msp.(*bccspmsp).getSigningIdentityFromConf(sigid)
	require.Error(t, err)
}

func TestMSPSetupNoCryptoConf(t *testing.T) {
	mspDir := configtest.GetDevMspDir()
	conf, err := GetLocalMSPConfig(mspDir, "SampleOrg")
	require.NoError(t, err)
	
	mspConf := &pbmsp.HyperchainMSPConfig{}
	err = proto.Unmarshal(conf.Config, mspConf)
	require.NoError(t, err)

	mspConf.CryptoConfig.HashAlgorithm = ""
	raw, err := proto.Marshal(mspConf)
	require.NoError(t, err)
	conf.Config = raw
	ks, err := bccsp.NewFileBasedKeyStore("", true)
	if err != nil {
		log.Fatal(err)
	}
	csp, err := bccsp.NewBCCSP(ks)
	if err != nil {
		log.Fatal(err)
	}
	newmsp := newBCCSPMSP(csp)
	err = newmsp.Setup(conf)
	require.NoError(t, err)
}

func TestGetters(t *testing.T) {
	typ := msp.GetType()
	require.Equal(t, typ, HYPERCHAIN)
	require.NotNil(t, msp.GetTLSIntermediateCerts())
	require.NotNil(t, msp.GetTLSRootCerts())	
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

var (
	msp  MSP
	conf *pbmsp.MSPConfig
)

func getLocalMSP(t *testing.T, dir string) MSP {
	conf, err := GetLocalMSPConfig(dir, "SampleOrg")
	require.NoError(t, err)

	ks, err := bccsp.NewFileBasedKeyStore("", true)
	require.NoError(t, err)
	csp, err := bccsp.NewBCCSP(ks)
	require.NoError(t, err)
	msp := newBCCSPMSP(csp)

	err = msp.Setup(conf)
	require.NoError(t, err)

	return msp
}

func getIdentity(t *testing.T, path string) Identity {
	mspDir := configtest.GetDevMspDir()
	pems, err := getPEMMaterialFromDir(filepath.Join(mspDir, path))
	require.NoError(t, err)

	id, _, err := msp.(*bccspmsp).getIdentityFromConf(pems[0])
	require.NoError(t, err)

	return id
}

func generateSelfSignedCert(t *testing.T, now time.Time) (*ecdsa.PrivateKey, *x509.Certificate) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	random := mrand.New(mrand.NewSource(time.Now().Unix()))
	template := x509.Certificate{
		SerialNumber: big.NewInt(random.Int63()),
		Subject: pkix.Name{
			CommonName:   "github.com",
			Organization: []string{"GitHub"},
			Country:      []string{"CN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  asn1.ObjectIdentifier{2, 5, 4, 42},
					Value: "Gopher",
				},
				{
					Type:  asn1.ObjectIdentifier{2, 5, 4, 6},
					Value: "Blockchain",
				},
			},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(1 * time.Hour),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		SubjectKeyId:          []byte{1, 2, 3, 4},
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{{1, 2, 3}, {2, 59, 1}},
		BasicConstraintsValid: true,
		IsCA:                  true,
		OCSPServer:            []string{"https://onlinecertificatestatusprotocol.nwpu.com"},
		IssuingCertificateURL: []string{"https://issuingcertificateurl.nwpu.com"},
		DNSNames:              []string{"https://dns.nwpu.com"},
		EmailAddresses:        []string{"1378406814@mail.nwpu.edu.cn"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("2001:4860:0:2001::68")},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{{1, 2, 3}},
		PermittedDNSDomains:   []string{"nwpu.com", ".nwpu.com"},
		CRLDistributionPoints: []string{"https://crl1.nwpu.com/ca1.crl", "https://crl2.nwpu.com/ca1.crl"},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 2, 3, 4},
				Value: []byte("extra extension"),
			},
		},
	}
	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(raw)
	require.NoError(t, err)
	return privateKey, cert
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/
