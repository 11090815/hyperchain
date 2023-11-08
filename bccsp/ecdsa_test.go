package bccsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
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

func TestSignatureLowS(t *testing.T) {
	type Signature struct {
		PrivateKey []byte `json:"private_key"`
		PublicKey  []byte `json:"public_key"`
		Sig        []byte `json:"sig"`
	}

	path, err := os.Getwd()
	require.NoError(t, err)
	path = filepath.Join(path, "testdata", "record.sig")

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdsaSK := &ecdsaPrivateKey{privateKey: privateKey}

	pemSK, err := privateKeyToPEM(privateKey)
	require.NoError(t, err)
	pemPK, err := publicKeyToPEM(&privateKey.PublicKey)
	require.NoError(t, err)

	signature := &Signature{
		PrivateKey: pemSK,
		PublicKey:  pemPK,
	}

	halfOrder := new(big.Int).Rsh(privateKey.Params().N, 1)

	msg := []byte("hello, world")
	hash := sha256.New()
	hash.Write(msg)
	digest := hash.Sum(nil)

	signer := &ecdsaSigner{}

	checkCh := make(chan struct{}, 1)

	go func() {
		for {
			sig, err := signer.Sign(ecdsaSK, digest, nil)
			require.NoError(t, err)

			r, s, err := UnmarshalECDSASignature(sig)
			require.NoError(t, err)

			if s.Cmp(halfOrder) == 1 {
				s.Sub(privateKey.Params().N, s)
				sig, err = MarshalECDSASignature(r, s)
				require.NoError(t, err)
				signature.Sig = sig
				raw, err := json.Marshal(signature)
				require.NoError(t, err)
				f.Write(raw)
				checkCh <- struct{}{}
				f.Sync()
				f.Close()
			}
		}
	}()

	<-checkCh

	content, err := os.ReadFile(filepath.Join(path))
	require.NoError(t, err)

	signature_ := &Signature{}
	err = json.Unmarshal(content, signature_)
	require.NoError(t, err)

	privateKey_, err := pemToPrivateKey(signature_.PrivateKey)
	require.NoError(t, err)
	ecdsaSK_ := &ecdsaPrivateKey{privateKey: privateKey_.(*ecdsa.PrivateKey)}

	verifier := &ecdsaPrivateKeyVerifier{}
	valid, err := verifier.Verify(ecdsaSK_, signature_.Sig, digest, nil)
	require.NoError(t, err)
	require.True(t, valid)
}
