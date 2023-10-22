package bccsp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type testStruct struct{}

func TestType(t *testing.T) {
	aesEncrypter := &aescbcpkcs7Encryptor{}
	opts := &testStruct{}
	_, err := aesEncrypter.Encrypt(nil, nil, opts)
	t.Log(err)
}

func TestAESEncryptDecrypt(t *testing.T) {
	key, err := GetRandomBytes(32)
	require.NoError(t, err)

	plaintext := []byte("你好，世界")
	ciphertext, err := AESCBCPKCS7Encrypt(key, plaintext)
	require.NoError(t, err)
	fmt.Println("输出密文：", ciphertext)

	decrypted, err := AESCBCPKCS7Decrypt(key, ciphertext)
	require.NoError(t, err)
	fmt.Println("输出解密后的明文：", string(decrypted))
}