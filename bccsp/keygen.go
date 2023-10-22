package bccsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

type KeyGenerator interface {
	KeyGen(opts KeyGenOpts) (key Key, err error)
}

type ecdsaKeyGenerator struct{}

func (kg *ecdsaKeyGenerator) KeyGen(opts KeyGenOpts) (Key, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating ecdsa key: [%s]", err.Error())
	}
	return &ecdsaPrivateKey{privateKey: privateKey}, nil
}

/*** 🐋 ***/

type aesKeyGenerator struct{}

// KeyGen 生成 256 比特长的 aes 密钥。
func (kg *aesKeyGenerator) KeyGen(opts KeyGenOpts) (Key, error) {
	key, err := GetRandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed generating aes key: [%s]", err.Error())
	}

	return &aesKey{key: key, exportable: false}, nil
}
