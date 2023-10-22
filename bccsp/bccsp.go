package bccsp

import (
	"hash"
	"io"
)

type BCCSP interface {
	// KeyGen 提供选项，生成与选项对应的密钥：
	//	- ECDSAKeyGenOpts：&ecdsaPrivateKey{}
	//	- AESKeyGenOpts：&aesKey{}
	KeyGen(opts KeyGenOpts) (Key, error)

	// KeyDeriv 根据密钥衍生算法衍生出新的密钥，需要提供选项，目前支持的选项：
	//	- AESKeyDerivOpts：衍生出新的 AES 密钥
	//	- ECDSAKeyDerivOpts：衍生出新的 ECDSA 密钥
	KeyDeriv(key Key, opts KeyDerivOpts) (Key, error)

	// KeyImport 导入密钥，需要提供选项，目前支持的选项：
	//	- ECDSAPKIXPublicKeyImportOpts：导入 ECDSA 公钥
	//	- ECDSAPrivateKeyImportOpts：导入 ECDSA 私钥
	//	- AESKeyImportOpts：导入 AES 密钥
	KeyImport(raw interface{}, opts KeyImportOpts) (Key, error)

	// GetKey 根据密钥的唯一标识符获取密钥。
	GetKey(ski []byte) (Key, error)

	// Hash 根据提供的选项，直接对消息进行哈希运算，得到消息的摘要，目前仅支持的选项是：
	//	- SHA256Opts：生成 256 比特的消息摘要。
	Hash(msg []byte, opts HashOpts) ([]byte, error)

	// GetHash 获得一个哈希函数，用于计算消息的哈希值，传入的选项目前仅支持：
	//	- SHA256Opts：获得一个 SHA256 哈希函数的实例
	GetHash(opts HashOpts) (hash.Hash, error)

	// Sign 根据提供的签名密钥，对消息摘要进行签名。
	Sign(key Key, digest []byte) ([]byte, error)

	// Verify 根据提供的密钥：
	//	- *ecdsaPrivateKey：提取其中的公钥，用公钥验证签名的合法性
	//	- *ecdsaPublickey：直接用公钥验证签名的合法性
	Verify(key Key, signature, digest []byte) (bool, error)

	// Encrypt 根据提供的密钥对明文进行加密获得密文，需要提供选项 EncryptOpts，目前仅支持：
	//	- AESCBCPKCS7ModeOpts：要么提供初始向量，要么提供伪随机数生成器，辅助加密过程
	Encrypt(key Key, plaintext []byte, opts EncryptOpts) ([]byte, error)

	// Decrypt 根据提供的密钥对密文进行解密。
	Decrypt(key Key, ciphertext []byte) ([]byte, error)
}

type Key interface {
	// Bytes 在允许的情况下，将密钥转换为原始的字节切片形式。
	Bytes() ([]byte, error)

	// SKI 返回该密钥的唯一标识符。
	//	- AES 返回其私钥的哈希值
	//	- ECDSA 返回其公钥的哈希值
	SKI() []byte

	// Symmetric 用来标识该密钥是否是对称密钥，如果是的话，则返回 true，否则返回 false。
	Symmetric() bool

	// IsPrivate 用来标识该密钥是否是私钥，如果是的话，则返回 true，否则返回 false。
	IsPrivate() bool

	// PublicKey 返回非对称密钥中的公钥，如果该密钥是对称密钥，调用该方法会返回错误。
	PublicKey() (Key, error)
}

type KeyStore interface {
	// ReadOnly 返回 true 的话，那么该 KeyStore 不可更改。
	ReadOnly() bool

	GetKey(ski []byte) (key Key, err error)

	// StoreKey 存储密钥，该方法在 ReadOnly 方法返回 true 的时候不可用。
	StoreKey(key Key) (err error)
}

/*** 🐋 ***/

// EncryptOpts 实际上是一个空的 interface{}。
type EncryptOpts interface{}

type AESCBCPKCS7ModeOpts struct {
	IV   []byte
	PRNG io.Reader
}

/*** 🐋 ***/

// 哈希选项，目前仅支持 SHA256。

type HashOpts interface {
	Algorithm() string
}

type SHA256Opts struct{}

func (opts *SHA256Opts) Algorithm() string {
	return SHA256
}

/*** 🐋 ***/

// 派生密钥选项。

type KeyDerivOpts interface {
	Algorithm() string
	Ephemeral() bool
}

// ECDSAKeyDerivOpts 用于衍生出新的 ecdsa 密钥的选项。
type ECDSAKeyDerivOpts struct {
	Temporary bool
	Expansion []byte
}

func (opts *ECDSAKeyDerivOpts) Algorithm() string {
	return ECDSAReRand
}

func (opts *ECDSAKeyDerivOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *ECDSAKeyDerivOpts) ExpansionValue() []byte {
	return opts.Expansion
}

// AESKeyDerivOpts 包含 HMAC 截断 256 比特密钥派生的选项。
type AESKeyDerivOpts struct {
	Temporary bool
	Arg       []byte
}

func (opts *AESKeyDerivOpts) Algorithm() string {
	return AESReRand
}

func (opts *AESKeyDerivOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *AESKeyDerivOpts) Argument() []byte {
	return opts.Arg
}

/*** 🐋 ***/

// 生成密钥选项，目前支持 P256 椭圆曲线 ECDSA 和 AES。

type KeyGenOpts interface {
	Algorithm() string
	Ephemeral() bool
}

// ECDSAKeyGenOpts 生成 256 比特 ecdsa 密钥的选项。
type ECDSAKeyGenOpts struct {
	Temporary bool
}

func (opts *ECDSAKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *ECDSAKeyGenOpts) Algorithm() string {
	return ECDSA
}

// AESKeyGenOpts 生成 256 比特 aes 密钥的选项。
type AESKeyGenOpts struct {
	Temporary bool
}

func (opts *AESKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *AESKeyGenOpts) Algorithm() string {
	return AES
}

/*** 🐋 ***/

// 导入密钥时的选项，目前

type KeyImportOpts interface {
	Algorithm() string
	Ephemeral() bool
}

type AESKeyImportOpts struct {
	Temporary bool
}

func (opts *AESKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *AESKeyImportOpts) Algorithm() string {
	return AES
}

type ECDSAPKIXPublicKeyImportOpts struct {
	Temporary bool
}

func (opts *ECDSAPKIXPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *ECDSAPKIXPublicKeyImportOpts) Algorithm() string {
	return ECDSA
}

type ECDSAPrivateKeyImportOpts struct {
	Temporary bool
}

func (opts *ECDSAPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *ECDSAPrivateKeyImportOpts) Algorithm() string {
	return ECDSA
}

/*** 🐋 ***/

const (
	ECDSAReRand = "ECDSA_RERAND"
	ECDSA       = "ECDSA"

	SHA256 = "SHA256"

	AES       = "AES"
	AESReRand = "AES_RERAND"
)
