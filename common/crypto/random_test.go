package crypto_test

import (
	"testing"

	"github.com/11090815/hyperchain/common/crypto"
	"github.com/stretchr/testify/require"
)

func TestGetRandomNonce(t *testing.T) {
	nonce, err := crypto.GetRandomNonce()
	require.NoError(t, err)
	require.Equal(t, crypto.NonceSize, len(nonce))
}
