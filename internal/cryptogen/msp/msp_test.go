package msp_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/11090815/hyperchain/internal/cryptogen/ca"
	"github.com/11090815/hyperchain/internal/cryptogen/msp"
	hcmsp "github.com/11090815/hyperchain/msp"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	testCAOrg              = "nwpu.edu.cn"
	testCAName             = "ca" + "." + testCAOrg
	testName               = "tom"
	testCountry            = "CN"
	testProvince           = "Shanxi"
	testLocality           = "Xian"
	testOrganizationalUnit = "11090815 Hyperchain"
	testStreetAddress      = "dongda street"
	testPostalCode         = "710000"
)

// /tmp/msp-test
var testDir = filepath.Join(os.TempDir(), "msp-test")

func testGenerateLocalMSP(t *testing.T, nodeOUs bool) {
	cleanup(testDir)

	err := msp.GenerateLocalMSP(testDir, testName, nil, &ca.CA{}, &ca.CA{}, msp.PEER, nodeOUs)
	require.Error(t, err)

	// /tmp/msp-test/ca
	caDir := filepath.Join(testDir, "ca")

	// /tmp/msp-test/tlsca
	tlsCADir := filepath.Join(testDir, "tlsca")

	// /tmp/msp-test/msp
	mspDir := filepath.Join(testDir, "msp")

	// /tmp/msp-test/tls
	tlsDir := filepath.Join(testDir, "tls")

	// 生成签名证书
	signCA, err := ca.NewCA(caDir, testCAOrg, testCAName, testCountry, testProvince, testLocality, testOrganizationalUnit, testStreetAddress, testPostalCode)
	require.NoError(t, err)

	// 生成 TLS 证书
	tlsCA, err := ca.NewCA(tlsCADir, testCAOrg, testCAName, testCountry, testProvince, testLocality, testOrganizationalUnit, testStreetAddress, testPostalCode)
	require.NoError(t, err)

	require.NotEmpty(t, signCA.SignCert.Subject.Country)
	require.Equal(t, testCountry, signCA.SignCert.Subject.Country[0])
	require.NotEmpty(t, signCA.SignCert.Subject.Province)
	require.Equal(t, testProvince, signCA.SignCert.Subject.Province[0])
	require.NotEmpty(t, signCA.SignCert.Subject.Locality)
	require.Equal(t, testLocality, signCA.SignCert.Subject.Locality[0])
	require.NotEmpty(t, signCA.SignCert.Subject.StreetAddress)
	require.Equal(t, testStreetAddress, signCA.SignCert.Subject.StreetAddress[0])
	require.NotEmpty(t, signCA.SignCert.Subject.PostalCode)
	require.Equal(t, testPostalCode, signCA.SignCert.Subject.PostalCode[0])
	require.NotEmpty(t, signCA.SignCert.Subject.OrganizationalUnit)
	require.Equal(t, testOrganizationalUnit, signCA.SignCert.Subject.OrganizationalUnit[0])

	err = msp.GenerateLocalMSP(testDir, testName, nil, signCA, tlsCA, msp.PEER, nodeOUs)
	require.NoError(t, err)

	mspFiles := []string{
		filepath.Join(mspDir, "cacerts", testCAName+"-cert.pem"),    // /tmp/msp-test/msp/cacerts/ca.nwpu.edu.cn-cert.pem
		filepath.Join(mspDir, "tlscacerts", testCAName+"-cert.pem"), // /tmp/msp-test/msp/tlscacerts/ca.nwpu.edu.cn-cert.pem
		filepath.Join(mspDir, "keystore"),                           // /tmp/msp-test/msp/keystore
		filepath.Join(mspDir, "signcerts", testName+"-cert.pem"),    // /tmp/msp-test/msp/signcerts/tom-cert.pem
	}
	if nodeOUs {
		mspFiles = append(mspFiles, filepath.Join(mspDir, "config.yaml"))
	} else {
		mspFiles = append(mspFiles, filepath.Join(mspDir, "admincerts", testName+"-cert.pem"))
	}

	tlsFiles := []string{
		filepath.Join(tlsDir, "ca.crt"),     // /tmp/msp-test/tls/ca.crt
		filepath.Join(tlsDir, "server.key"), // /tmp/msp-test/tls/server.key
		filepath.Join(tlsDir, "server.crt"), // /tmp/msp-test/tls/server.crt
	}

	for _, file := range mspFiles {
		require.Equal(t, true, isFileExist(file))
	}

	for _, file := range tlsFiles {
		require.Equal(t, true, isFileExist(file))
	}

	err = msp.GenerateLocalMSP(testDir, testName, nil, signCA, tlsCA, msp.CLIENT, nodeOUs)
	require.NoError(t, err)

	for _, file := range mspFiles {
		require.Equal(t, true, isFileExist(file))
	}

	for _, file := range tlsFiles {
		require.Equal(t, true, isFileExist(file))
	}

	tlsCA.Name = "test/fail"
	err = msp.GenerateLocalMSP(testDir, testName, nil, signCA, tlsCA, msp.CLIENT, nodeOUs)
	require.Error(t, err)
	signCA.Name = "test/fail"
	err = msp.GenerateLocalMSP(testDir, testName, nil, signCA, tlsCA, msp.ORDERER, nodeOUs)
	require.Error(t, err)
	t.Log(err)
	// cleanup(testDir)
}

func TestGenerateLocalMSPWithNodeOUs(t *testing.T) {
	testGenerateLocalMSP(t, true)
}

func TestGenerateLocalMSPWithoutNodeOUs(t *testing.T) {
	testGenerateLocalMSP(t, false)
}

func testGenerateVerifyingMSP(t *testing.T, nodeOUs bool) {
	cleanup(testDir)

	caDir := filepath.Join(testDir, "ca")       // /tmp/msp-test/ca
	tlsCADir := filepath.Join(testDir, "tlsca") // /tmp/msp-test/tlsca
	mspDir := filepath.Join(testDir, "msp")     // /tmp/msp-test/msp

	signCA, err := ca.NewCA(caDir, testCAOrg, testCAName, testCountry, testProvince, testLocality, testOrganizationalUnit, testStreetAddress, testPostalCode)
	require.NoError(t, err)

	tlsCA, err := ca.NewCA(tlsCADir, testCAOrg, testCAName, testCountry, testProvince, testLocality, testOrganizationalUnit, testStreetAddress, testPostalCode)
	require.NoError(t, err)

	err = msp.GenerateVerifyingMSP(mspDir, signCA, tlsCA, nodeOUs)
	require.NoError(t, err)

	files := []string{
		filepath.Join(mspDir, "cacerts", testCAName+"-cert.pem"),    // /tmp/msp-test/msp/cacerts/ca.nwpu.edu.cn-cert.pem
		filepath.Join(mspDir, "tlscacerts", testCAName+"-cert.pem"), // /tmp/msp-test/msp/tlscacerts/ca.nwpu.edu.cn-cert.pem
	}

	if nodeOUs {
		files = append(files, filepath.Join(mspDir, "config.yaml"))
	} else {
		files = append(files, filepath.Join(mspDir, "admincerts", testCAName+"-cert.pem")) // /tmp/msp-test/msp/admincerts/ca.nwpu.edu.cn-cert.pem
	}

	for _, file := range files {
		require.Equal(t, true, isFileExist(file))
	}

	tlsCA.Name = "test/fail"
	err = msp.GenerateVerifyingMSP(mspDir, signCA, tlsCA, nodeOUs)
	require.Error(t, err)
	signCA.Name = "test/fail"
	err = msp.GenerateVerifyingMSP(mspDir, signCA, tlsCA, nodeOUs)
	require.Error(t, err)
	t.Log(err)
	cleanup(testDir)
}

func TestGenerateVerifyingMSPWithNodeOUs(t *testing.T) {
	testGenerateVerifyingMSP(t, true)
}

func TestGenerateVerifyingMSPWithoutNodeOUs(t *testing.T) {
	testGenerateVerifyingMSP(t, false)
}

func TestExportConfig(t *testing.T) {
	path := filepath.Join(testDir, "export-test")
	configFile := filepath.Join(path, "config.yaml")
	caFile := "ca.pem"
	t.Log(path)
	err := os.MkdirAll(path, os.FileMode(0755))
	require.NoError(t, err)

	err = msp.ExportConfig(path, caFile, true)
	require.NoError(t, err)

	configBytes, err := os.ReadFile(configFile)
	require.NoError(t, err)

	config := &hcmsp.Configuration{}
	err = yaml.Unmarshal(configBytes, config)
	require.NoError(t, err)

	require.Equal(t, caFile, config.NodeOUs.ClientOUIdentifier.Certificate)
	require.Equal(t, msp.CLIENTOU, config.NodeOUs.ClientOUIdentifier.OrganizationalUnitIdentifier)
	require.Equal(t, caFile, config.NodeOUs.PeerOUIdentifier.Certificate)
	require.Equal(t, msp.PEEROU, config.NodeOUs.PeerOUIdentifier.OrganizationalUnitIdentifier)
	require.Equal(t, caFile, config.NodeOUs.AdminOUIdentifier.Certificate)
	require.Equal(t, msp.ADMINOU, config.NodeOUs.AdminOUIdentifier.OrganizationalUnitIdentifier)
	require.Equal(t, caFile, config.NodeOUs.OrdererOUIdentifier.Certificate)
	require.Equal(t, msp.ORDEREROU, config.NodeOUs.OrdererOUIdentifier.OrganizationalUnitIdentifier)
}

func cleanup(dir string) {
	os.RemoveAll(dir)
}

func isFileExist(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true
}
