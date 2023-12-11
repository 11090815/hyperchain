package msp

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/11090815/hyperchain/bccsp"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRevocation(t *testing.T) {
	t.Run("ValidCRLSignature", func(t *testing.T) {
		msp := getLocalMSP(t, "testdata/revocation")
		id, err := msp.GetDefaultSigningIdentity()
		require.NoError(t, err)

		err = id.Validate()
		require.Error(t, err)
		t.Log(err)
	})

	t.Run("MalformedCRLSignature", func(t *testing.T) {
		conf, err := GetLocalMSPConfig("testdata/revocation", "SampleOrg")
		require.NoError(t, err)

		var mspConfig pbmsp.HyperchainMSPConfig
		err = proto.Unmarshal(conf.Config, &mspConfig)
		require.NoError(t, err)
		require.Len(t, mspConfig.RevocationList, 1)
		block, _ := pem.Decode(mspConfig.RevocationList[0])
		crl, err := x509.ParseRevocationList(block.Bytes)
		require.NoError(t, err)
		t.Log("crl signature:", hex.EncodeToString(crl.Signature))

		var sig struct{ R, S *big.Int }
		_, err = asn1.Unmarshal(crl.Signature, &sig)
		require.NoError(t, err)

		extendedSig := struct{ R, S, T *big.Int }{R: sig.R, S: sig.S, T: big.NewInt(100)}
		longSigBytes, err := asn1.Marshal(extendedSig)
		require.NoError(t, err)

		crl.Signature = longSigBytes
		crlBytes, err := asn1.Marshal(*crl)
		require.NoError(t, err)
		mspConfig.RevocationList[0] = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})

		conf.Config, err = proto.Marshal(&mspConfig)
		require.NoError(t, err)

		ks, err := bccsp.NewFileBasedKeyStore(filepath.Join("testdata/revocation", "keystore"), true)
		require.NoError(t, err)
		csp, err := bccsp.NewBCCSP(ks)
		require.NoError(t, err)

		msp := newBCCSPMSP(csp)
		err = msp.Setup(conf)
		require.Error(t, err)
	})
}

func TestIdentityPolicyPrincipalAganistRevokedIdentity(t *testing.T) {
	msp := getLocalMSP(t, "testdata/revocation")
	id, err := msp.GetDefaultSigningIdentity()
	require.NoError(t, err)
	
	serializedID, err := id.Serialize()
	require.NoError(t, err)

	principal := &pbmsp.MSPPrincipal{
		PrincipalClassification: pbmsp.MSPPrincipal_IDENTITY,
		Principal: serializedID,
	}

	err = id.SatisfiesPrincipal(principal)
	require.Error(t, err)
	t.Log(err)
}

func TestRevokedIntermediateCA(t *testing.T) {
	dir := "testdata/revokedica"
	conf, err := GetLocalMSPConfig(dir, "SampleOrg")
	require.NoError(t, err)
	
	csp, err := bccsp.NewBCCSP(bccsp.NewFakeKeyStore())
	require.NoError(t, err)
	msp := newBCCSPMSP(csp)

	ks, err := bccsp.NewFileBasedKeyStore(filepath.Join(dir, "keystore"), true)
	require.NoError(t, err)
	csp2, err := bccsp.NewBCCSP(ks)
	require.NoError(t, err)

	msp.(*bccspmsp).csp = csp2

	err = msp.Setup(conf)
	require.Error(t, err)
	t.Log(err)
}
