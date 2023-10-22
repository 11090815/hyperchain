package bccsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECDSAKeyDeriv(t *testing.T) {
	var hash func() hash.Hash = sha256.New
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := []byte("message")
	h1 := hash()
	h1.Write(msg)
	digest := h1.Sum(nil)
	sig1, err := privateKey.Sign(rand.Reader, digest, nil)
	require.NoError(t, err)
	ok := ecdsa.VerifyASN1(&privateKey.PublicKey, digest, sig1)
	require.True(t, ok)

	key := &ecdsaPrivateKey{privateKey: privateKey}
	opts := ECDSAKeyDerivOpts{Expansion: []byte{1, 2, 3, 4}}

	deriver := &ecdsaPrivateKeyDeriver{}

	derivedKey, err := deriver.KeyDeriv(key, &opts)
	require.NoError(t, err)

	derivedPrivateKey, ok := derivedKey.(*ecdsaPrivateKey)
	require.True(t, ok)

	sig2, err := derivedPrivateKey.privateKey.Sign(rand.Reader, digest, nil)
	require.NoError(t, err)
	ok = ecdsa.VerifyASN1(&derivedPrivateKey.privateKey.PublicKey, digest, sig2)
	require.True(t, ok)

	ok = ecdsa.VerifyASN1(&privateKey.PublicKey, digest, sig2)
	require.False(t, ok)
}

func TestDerivAESKey(t *testing.T) {
	key, err := GetRandomBytes(32)
	require.NoError(t, err)

	plaintext := []byte("hello, world")

	aesK := &aesKey{key: key}
	deriver := &aesKeyDeriver{}

	opts1 := &AESKeyDerivOpts{Arg: []byte{'a', 'b', 'c', 1, 2, 3}}
	derivedKey1, err := deriver.KeyDeriv(aesK, opts1)
	require.NoError(t, err)
	derivedAESKey, ok := derivedKey1.(*aesKey)
	require.True(t, ok)

	encrypter := &aescbcpkcs7Encryptor{}
	opts := &AESCBCPKCS7ModeOpts{PRNG: rand.Reader}
	ciphertext, err := encrypter.Encrypt(derivedAESKey, plaintext, opts)
	require.NoError(t, err)

	decrypter := &aescbcpkcs7Decryptor{}
	decrypted, err := decrypter.Decrypt(derivedAESKey, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestHMAC(t *testing.T) {
	key, _ := GetRandomBytes(32)
	mac := hmac.New(sha256.New, key)

	mac.Write([]byte{1, 2, 3, 4, 5})

	fmt.Println(len(mac.Sum(nil)), ":", mac.Sum(nil))
}
