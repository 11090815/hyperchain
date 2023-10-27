package csp_test

import (
	"os"
	"testing"

	"github.com/11090815/hyperchain/internal/cryptogen/csp"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndLoadPrivateKey(t *testing.T) {
	_, err := os.Stat("testdata")
	if err != nil && os.IsNotExist(err) {
		err = os.Mkdir("testdata", os.FileMode(0755))
		require.NoError(t, err)
	}

	privateKey, err := csp.GeneratePrivateKey("testdata")
	require.NoError(t, err)

	loadedPrivateKey, err := csp.LoadPrivateKey("testdata")
	require.NoError(t, err)

	require.Equal(t, privateKey, loadedPrivateKey)
}
