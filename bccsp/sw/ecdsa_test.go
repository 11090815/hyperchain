package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignAndVerify(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ePrivateKey := &ecdsaPrivateKey{privateKey: key}
	ePublicKey := &ecdsaPublicKey{publicKey: &key.PublicKey}

	msg := []byte("轻舟已过万重山！")
	// digest := sha256.Sum256(msg)
	hash := sha256.New()
	hash.Write(msg)
	digest := hash.Sum(nil)

	signer := &ecdsaSigner{}
	signature, err := signer.Sign(ePrivateKey, digest, nil)
	require.NoError(t, err)

	privateVerifier := &ecdsaPrivateKeyVerifier{}
	publicVerifier := &ecdsaPublicKeyVerifier{}

	v1, err := privateVerifier.Verify(ePrivateKey, signature, digest, nil)
	require.NoError(t, err)
	require.True(t, v1)

	v2, err := publicVerifier.Verify(ePublicKey, signature, digest, nil)
	require.NoError(t, err)
	require.True(t, v2)
}

func TestCheckSha256(t *testing.T) {
	msg := []byte("轻舟已过万重山！")
	digest1 := sha256.Sum256(msg)

	hash := sha256.New()
	hash.Write(msg)
	digest2 := hash.Sum(nil)

	fmt.Println("digest1:", hex.EncodeToString(digest1[:]))
	fmt.Println("digest2:", hex.EncodeToString(digest2))

	require.Equal(t, digest1[:], digest2)
}
