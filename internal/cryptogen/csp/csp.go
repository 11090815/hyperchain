package csp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/11090815/hyperchain/bccsp"
)

// LoadPrivateKey 给定一个存储 ecdsa 私钥的目录路径，从中加载一个 ecdsa 私钥，返回 *ecdsa.PrivateKey。
func LoadPrivateKey(keystorePath string) (*ecdsa.PrivateKey, error) {
	var key *ecdsa.PrivateKey
	walkFunc := func(path string, info os.FileInfo, err error) error {
		if !strings.HasSuffix(path, "private_key") {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		key, err = parsePrivateKeyPEM(raw)
		if err != nil {
			return fmt.Errorf("the private key storing in [%s] is invalid: [%s]", path, err.Error())
		}
		return nil
	}

	err := filepath.Walk(keystorePath, walkFunc)
	if err != nil {
		return nil, err
	}

	return key, err
}

// GeneratePrivateKey 传入存储私钥的目录地址，利用 ecdsa.GenerateKey(elliptic.P256(), rand.Reader) 方法随机生成一个私钥，
// 然后将该私钥转换为 ASN.1 DER PEM 编码格式，存储到文件中，然后返回 *ecdsa.PrivateKey。
func GeneratePrivateKey(keystorePath string) (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating private key: [%s]", err.Error())
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed generating private key: [%s]", err.Error())
	}

	p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	err = os.WriteFile(filepath.Join(keystorePath, "private_key"), p, os.FileMode(0600))
	if err != nil {
		return nil, fmt.Errorf("failed generating private key: [%s]", err.Error())
	}

	return privateKey, nil
}

type ECDSASigner struct {
	PrivateKey *ecdsa.PrivateKey
}

// Public 返回 *ecdsa.Public。
func (signer *ECDSASigner) Public() crypto.PublicKey {
	return &signer.PrivateKey.PublicKey
}

// Sign 执行以下步骤得到签名：
//   - r, s, _ := ecdsa.Sign(rand.Reader, key, digest)
//   - sig, err := bccsp.MarshalECDSASignature(r, s)
//   - return sig, err
func (signer *ECDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand, signer.PrivateKey, digest)
	if err != nil {
		return nil, err
	}

	return bccsp.MarshalECDSASignature(r, s)
}

// parsePrivateKeyPEM 将 ASN.1 DER PEM 格式的 ecdsa 私钥转换为 *ecdsa.PrivateKey。
func parsePrivateKeyPEM(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("failed decoding pem format private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing asn.1 der format private key: [%s]", err.Error())
	}
	sk, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed parsing pem format private key: [invalid key type [%T], only support *ecdsa.PrivateKey]", key)
	}

	return sk, nil
}
