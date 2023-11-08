package bccsp_test

import (
	"crypto/rand"
	"testing"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/stretchr/testify/require"
)

func TestCSPSignAndVerify(t *testing.T) {
	csp, err := bccsp.NewBCCSP(nil)
	require.NoError(t, err)

	key, err := csp.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	require.Error(t, err)

	msg := []byte("hello, world")
	digest, err := csp.Hash(msg, &bccsp.SHA256Opts{})
	require.NoError(t, err)

	signature, err := csp.Sign(key, digest, nil)
	require.NoError(t, err)

	publicKey, err := key.PublicKey()
	require.NoError(t, err)
	valid, err := csp.Verify(publicKey, signature, digest, nil)
	require.NoError(t, err)
	require.True(t, valid)

	valid, err = csp.Verify(key, signature, digest, nil)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestCSPEncryptAndDecrypt(t *testing.T) {
	csp, err := bccsp.NewBCCSP(nil)
	require.NoError(t, err)

	key, err := csp.KeyGen(&bccsp.AESKeyGenOpts{Temporary: true})
	require.NoError(t, err)

	msg := []byte("hello, world")

	ciphertext, err := csp.Encrypt(key, msg, &bccsp.AESCBCPKCS7ModeOpts{PRNG: rand.Reader})
	require.NoError(t, err)

	plaintext, err := csp.Decrypt(key, ciphertext, nil)
	require.NoError(t, err)
	require.Equal(t, plaintext, msg)
}
