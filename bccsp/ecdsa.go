package bccsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

type Signer interface {
	Sign(key Key, digest []byte, opts SignerOpts) (signature []byte, err error)
}

type Verifier interface {
	Verify(key Key, signature []byte, digest []byte, opts SignerOpts) (valid bool, err error)
}

type ecdsaSigner struct{}

// Sign 给定的 Key 的实际变量类型必须是 *ecdsaPrivateKey。
func (s *ecdsaSigner) Sign(key Key, digest []byte, opts SignerOpts) ([]byte, error) {
	return signECDSA(key.(*ecdsaPrivateKey).privateKey, digest)
}

type ecdsaPrivateKeyVerifier struct{}

// Verify 给定的 Key 的实际变量类型必须是 *ecdsaPrivateKey。
func (v *ecdsaPrivateKeyVerifier) Verify(key Key, signature, digest []byte, opts SignerOpts) (bool, error) {
	return verifyECDSA(&key.(*ecdsaPrivateKey).privateKey.PublicKey, signature, digest)
}

type ecdsaPublicKeyVerifier struct{}

// Verify 给定的 Key 的实际变量类型必须是 *ecdsaPublicKey。
func (v *ecdsaPublicKeyVerifier) Verify(key Key, signature, digest []byte, opts SignerOpts) (bool, error) {
	return verifyECDSA(key.(*ecdsaPublicKey).publicKey, signature, digest)
}

// signECDSA 利用给定的 ECC 密钥对给定的消息摘要进行签名，得到 r 和 s 两个大整数，然后利用 asn1.Marshal 方法将两个大整数序列化成一个字节切片，得到最终的签名。
func signECDSA(k *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}
	return MarshalECDSASignature(r, s)
}

// verifyECDSA 利用给定的 ECC 公钥对给定的签名进行验证。
func verifyECDSA(k *ecdsa.PublicKey, signature, digest []byte) (bool, error) {
	r, s, err := UnmarshalECDSASignature(signature)
	if err != nil {
		return false, fmt.Errorf("failed unmarshaling signature: [%s]", err.Error())
	}

	return ecdsa.Verify(k, digest, r, s), nil
}

type ECDSASignature struct {
	R, S *big.Int
}

func MarshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ECDSASignature{R: r, S: s})
}

func UnmarshalECDSASignature(raw []byte) (r *big.Int, s *big.Int, err error) {
	sig := &ECDSASignature{}
	if _, err = asn1.Unmarshal(raw, sig); err != nil {
		return nil, nil, err
	}

	return sig.R, sig.S, nil
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type ecdsaPrivateKey struct {
	privateKey *ecdsa.PrivateKey
}

func (*ecdsaPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("ecdsa private key doesn't support this method")
}

func (key *ecdsaPrivateKey) SKI() []byte {
	if key.privateKey == nil {
		return nil
	}

	raw := elliptic.Marshal(key.privateKey.Curve, key.privateKey.X, key.privateKey.Y)

	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (*ecdsaPrivateKey) Symmetric() bool {
	return false
}

func (*ecdsaPrivateKey) IsPrivate() bool {
	return true
}

func (key *ecdsaPrivateKey) PublicKey() (Key, error) {
	return &ecdsaPublicKey{publicKey: &key.privateKey.PublicKey}, nil
}

type ecdsaPublicKey struct {
	publicKey *ecdsa.PublicKey
}

func (key *ecdsaPublicKey) Bytes() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key.publicKey)
}

func (key *ecdsaPublicKey) SKI() []byte {
	if key.publicKey == nil {
		return nil
	}

	raw := elliptic.Marshal(key.publicKey.Curve, key.publicKey.X, key.publicKey.Y)

	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (*ecdsaPublicKey) Symmetric() bool {
	return false
}

func (*ecdsaPublicKey) IsPrivate() bool {
	return false
}

func (key *ecdsaPublicKey) PublicKey() (Key, error) {
	return key, nil
}
