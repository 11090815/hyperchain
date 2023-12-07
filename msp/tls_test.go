package msp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTLSCAs(t *testing.T) {
	msp := getLocalMSP(t, "../sampleconfig/msp")
	id, err := msp.GetDefaultSigningIdentity()
	require.NoError(t, err)

	err = msp.Validate(id.GetPublicVersion())
	require.NoError(t, err)

	tlsRootCerts := msp.GetTLSRootCerts()
	require.Len(t, tlsRootCerts, 1)

	tlsRootCerts2, err := getPEMMaterialFromDir("../sampleconfig/msp/tlscacerts")
	require.NoError(t, err)
	require.Len(t, tlsRootCerts2, 1)
	require.Equal(t, tlsRootCerts[0], tlsRootCerts2[0])

	tlsIntermediateCerts := msp.GetTLSIntermediateCerts()
	require.Len(t, tlsIntermediateCerts, 1)
	tlsIntermediateCerts2, err := getPEMMaterialFromDir("../sampleconfig/msp/tlsintermediatecerts")
	require.NoError(t, err)
	require.Len(t, tlsIntermediateCerts2, 1)
	require.Equal(t, tlsIntermediateCerts[0], tlsIntermediateCerts2[0])
}
