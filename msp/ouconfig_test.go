package msp

import (
	"testing"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/stretchr/testify/require"
)

func TestBadConfigOU(t *testing.T) {
	msp := getLocalMSP(t, "testdata/badconfigou")
	id, err := msp.GetDefaultSigningIdentity()
	require.NoError(t, err)
	err = id.Validate()
	require.Error(t, err)
	t.Log(err)
}

func TestBadConfigOUCert(t *testing.T) {
	conf, err := GetLocalMSPConfig("testdata/badconfigoucert", "SampleOrg")
	require.NoError(t, err)

	ks, err := bccsp.NewFileBasedKeyStore("testdata/badconfigoucert/keystore", true)
	require.NoError(t, err)

	csp, err := bccsp.NewBCCSP(ks)
	require.NoError(t, err)

	msp := newBCCSPMSP(csp)

	err = msp.Setup(conf)
	require.Error(t, err)
	t.Log(err)
}

func TestValidateIntermediateConfigOU(t *testing.T) {
	msp := getLocalMSP(t, "testdata/external")
	id, err := msp.GetDefaultSigningIdentity()
	require.NoError(t, err)
	
	err = id.Validate()
	require.NoError(t, err)

	conf, err := GetLocalMSPConfig("testdata/external", "SampleOrg")
	require.NoError(t, err)

	csp1, err := bccsp.NewBCCSP(bccsp.NewFakeKeyStore())
	require.NoError(t, err)

	msp = newBCCSPMSP(csp1)

	ks, err := bccsp.NewFileBasedKeyStore("testdata/external/keystore", true)
	require.NoError(t, err)
	csp2, err := bccsp.NewBCCSP(ks)
	require.NoError(t, err)

	msp.(*bccspmsp).csp = csp2
	err = msp.Setup(conf)
	require.NoError(t, err)
}
