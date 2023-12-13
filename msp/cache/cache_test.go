package cache

import (
	"testing"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/msp"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
	"github.com/stretchr/testify/require"
)

func TestNewCacheMsp(t *testing.T) {
	i, err := New(nil)
	require.Error(t, err)
	require.Nil(t, i)
	require.Contains(t, err.Error(), "invalid given msp, it should not be nil")

	theMsp := msp.New(nil)
	i, err = New(theMsp)
	require.NoError(t, err)
	require.NotNil(t, i)
}

func TestSetup(t *testing.T) {
	csp, err := bccsp.NewBCCSP(nil)
	require.NoError(t, err)
	theMsp := msp.New(csp)
	i, err := New(theMsp)
	require.NoError(t, err)

	theMsp.Setup(&pbmsp.MSPConfig{})
	err = i.Setup(nil)
	require.Error(t, err)
	require.Equal(t, 0, i.(*cachedMSP).deserializedIdentityCache.len())
	require.Equal(t, 0, i.(*cachedMSP).satisfiesPrincipalCache.len())
	require.Equal(t, 0, i.(*cachedMSP).validateIdentityCache.len())
}
