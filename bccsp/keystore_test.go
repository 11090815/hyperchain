package bccsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/stretchr/testify/require"
)

func TestFileMode(t *testing.T) {
	t.Log(os.ModeAppend | os.ModeCharDevice | os.ModeDir)
	t.Log(os.ModeTemporary)
	t.Log(os.FileMode(0755))
}

func TestStoreAndLoad(t *testing.T) {
	hlogging.Init(hlogging.Config{Format: hlogging.ShortFuncFormat})
	hlogging.ActivateSpec("bccsp_ks=debug")

	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "bccspks")
	fmt.Println("path:", path)

	ks, err := NewFileBasedKeyStore(path, false)
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pk := &ecdsaPublicKey{publicKey: &privateKey.PublicKey}
	sk := &ecdsaPrivateKey{privateKey: privateKey}

	err = ks.StoreKey(pk)
	require.NoError(t, err)

	err = ks.StoreKey(sk)
	require.NoError(t, err)

	files, err := os.ReadDir(path)
	require.NoError(t, err)

	for _, f := range files {
		if strings.HasSuffix(f.Name(), "public_key") {
			fmt.Println("public key:", f.Name())
			index := strings.LastIndex(f.Name(), "_")
			fmt.Println("ski of public:", f.Name()[:index])
			fmt.Println()
		} else if strings.HasSuffix(f.Name(), "private_key") {
			fmt.Println("private key:", f.Name())
			index := strings.LastIndex(f.Name(), "_")
			fmt.Println("ski of private:", f.Name()[:index])
			fmt.Println()
		}
	}

	key, err := ks.GetKey(pk.SKI())
	require.NoError(t, err)

	switch key.(type) {
	case *ecdsaPrivateKey:
		fmt.Println("get a private key")
	case *ecdsaPublicKey:
		fmt.Println("get a public key")
	default:
		fmt.Println("unknown key type")
	}
}

func TestStore(t *testing.T) {
	hlogging.ActivateSpec("bccsp_ks=debug")

	path, _ := os.Getwd()
	path = filepath.Join(path, "testdata")

	ks, err := NewFileBasedKeyStore(path, false)
	require.NoError(t, err)

	aesRaw, err := GetRandomBytes(32)
	require.NoError(t, err)
	aesK := &aesKey{key: aesRaw}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdsaSK := &ecdsaPrivateKey{privateKey: privateKey}
	ecdsaPK := &ecdsaPublicKey{publicKey: &privateKey.PublicKey}

	err = ks.StoreKey(aesK)
	require.NoError(t, err)

	err = ks.StoreKey(ecdsaPK)
	require.NoError(t, err)

	err = ks.StoreKey(ecdsaSK)
	require.NoError(t, err)
}

func TestData(t *testing.T) {
	path, _ := os.Getwd()
	path = filepath.Join(path, "testdata")

	ks, err := NewFileBasedKeyStore(path, false)
	require.NoError(t, err)

	files, err := os.ReadDir(path)
	require.NoError(t, err)

	skis := make(map[string]struct{})

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		index := strings.Index(f.Name(), "_")
		if index == -1 {
			continue
		}
		skis[f.Name()[:index]] = struct{}{}
	}

	for ski, _ := range skis {
		ski, _ := hex.DecodeString(ski)

		key, err := ks.GetKey(ski)
		require.NoError(t, err)

		switch key.(type) {
		case *ecdsaPrivateKey:
			fmt.Println("ecdsa private key")
		case *ecdsaPublicKey:
			fmt.Println("ecdsa public key")
		case *aesKey:
			fmt.Println("aes key")
		default:
			fmt.Printf("unknown key type [%T]\n", key)
		}
	}
}
