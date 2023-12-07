package bccsp

import (
	"crypto"
	"hash"
	"io"

	"github.com/11090815/hyperchain/common/mathlib"
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
	//	- X509PublicKeyImportOpts：导入 x509 公钥
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
	Sign(key Key, digest []byte, opts SignerOpts) ([]byte, error)

	// Verify 根据提供的密钥：
	//	- *ecdsaPrivateKey：提取其中的公钥，用公钥验证签名的合法性
	//	- *ecdsaPublickey：直接用公钥验证签名的合法性
	Verify(key Key, signature, digest []byte, opts SignerOpts) (bool, error)

	// Encrypt 根据提供的密钥对明文进行加密获得密文，需要提供选项 EncryptOpts，目前仅支持：
	//	- AESCBCPKCS7ModeOpts：要么提供初始向量，要么提供伪随机数生成器，辅助加密过程
	Encrypt(key Key, plaintext []byte, opts EncryptOpts) ([]byte, error)

	// Decrypt 根据提供的密钥对密文进行解密。
	Decrypt(key Key, ciphertext []byte, opts DecryptOpts) ([]byte, error)
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

/* 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 */

type SignerOpts interface {
	crypto.SignerOpts
}

/*** 🐋 ***/

// EncryptOpts 实际上是一个空的 interface{}。
type EncryptOpts interface{}

type DecryptOpts interface{}

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

type X509PublicKeyImportOpts struct {
	Temporary bool
}

func (opts *X509PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *X509PublicKeyImportOpts) Algorithm() string {
	return X509Certificate
}

/*** 🐋 ***/

const (
	ECDSAReRand     = "ECDSA_RERAND"
	ECDSA           = "ECDSA"
	X509Certificate = "X509Certificate"

	SHA2   = "SHA2"
	SHA256 = "SHA256"

	AES       = "AES"
	AESReRand = "AES_RERAND"

	IDEMIX = "IDEMIX"
)

/* 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 */

// idemix

type IdemixCredentialRequestSignerOpts struct {
	// 证书中包含的属性的索引列表。
	Attributes []int

	// 签发者的公钥。
	IssuerPK Key

	// IssuerNonce 由签发人生成，客户端使用它来生成凭据请求。签发人收到凭据请求后，会检查 nonce 是否相同。
	IssuerNonce []byte

	// 被使用的哈希函数。
	H crypto.Hash
}

func (o *IdemixCredentialRequestSignerOpts) HashFunc() crypto.Hash {
	return o.H
}

func (o *IdemixCredentialRequestSignerOpts) IssuerPublicKey() Key {
	return o.IssuerPK
}

// IdemixIssuerKeyGenOpts contains the options for the Idemix Issuer key-generation.
// A list of attribytes may be optionally passed
type IdemixIssuerKeyGenOpts struct {
	// Temporary tells if the key is ephemeral
	Temporary bool
	// AttributeNames is a list of attributes
	AttributeNames []string
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (*IdemixIssuerKeyGenOpts) Algorithm() string {
	return IDEMIX
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (o *IdemixIssuerKeyGenOpts) Ephemeral() bool {
	return o.Temporary
}

// IdemixAttributeType represents the type of an idemix attribute
type IdemixAttributeType int

type IdemixAttribute struct {
	// Type is the attribute's type
	Type IdemixAttributeType
	// Value is the attribute's value
	Value interface{}
}

// IdemixCredentialSignerOpts contains the options to produce a credential starting from a credential request
type IdemixCredentialSignerOpts struct {
	// Attributes to include in the credentials. IdemixHiddenAttribute is not allowed here
	Attributes []IdemixAttribute
	// IssuerPK is the public-key of the issuer
	IssuerPK Key
	// HashFun is the hash function to be used
	H crypto.Hash
}

// HashFunc returns an identifier for the hash function used to produce
// the message passed to Signer.Sign, or else zero to indicate that no
// hashing was done.
func (o *IdemixCredentialSignerOpts) HashFunc() crypto.Hash {
	return o.H
}

func (o *IdemixCredentialSignerOpts) IssuerPublicKey() Key {
	return o.IssuerPK
}

// VerificationType describes the type of verification that is required
type VerificationType int

type NymEIDAuditData struct {
	// RNymEid is the randomness used to generate the EID Nym
	RNymEid *mathlib.Zr

	// EID is the enrollment id
	EID *mathlib.Zr
}

type IdemixSignerMetadata struct {
	NymEIDAuditData *NymEIDAuditData
}

// SignatureType describes the type of idemix signature
type SignatureType int

// RevocationAlgorithm identifies the revocation algorithm
type RevocationAlgorithm int32

// IdemixIssuerPublicKeyImportOpts contains the options for importing of an Idemix issuer public key.
type IdemixIssuerPublicKeyImportOpts struct {
	Temporary bool
	// AttributeNames is a list of attributes to ensure the import public key has
	AttributeNames []string
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (*IdemixIssuerPublicKeyImportOpts) Algorithm() string {
	return IDEMIX
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (o *IdemixIssuerPublicKeyImportOpts) Ephemeral() bool {
	return o.Temporary
}

// IdemixIssuerKeyImportOpts contains the options for importing of an Idemix issuer public key.
type IdemixIssuerKeyImportOpts struct {
	Temporary bool
	// AttributeNames is a list of attributes to ensure the import public key has
	AttributeNames []string
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (*IdemixIssuerKeyImportOpts) Algorithm() string {
	return IDEMIX
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (o *IdemixIssuerKeyImportOpts) Ephemeral() bool {
	return o.Temporary
}

// IdemixNymSignerOpts contains the options to generate an idemix pseudonym signature.
type IdemixNymSignerOpts struct {
	// Nym is the pseudonym to be used
	Nym Key
	// IssuerPK is the public-key of the issuer
	IssuerPK Key
	// H is the hash function to be used
	H crypto.Hash
}

// HashFunc returns an identifier for the hash function used to produce
// the message passed to Signer.Sign, or else zero to indicate that no
// hashing was done.
func (o *IdemixNymSignerOpts) HashFunc() crypto.Hash {
	return o.H
}

// IdemixNymKeyDerivationOpts contains the options to create a new unlinkable pseudonym from a
// credential secret key with the respect to the specified issuer public key
type IdemixNymKeyDerivationOpts struct {
	// Temporary tells if the key is ephemeral
	Temporary bool
	// IssuerPK is the public-key of the issuer
	IssuerPK Key
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (*IdemixNymKeyDerivationOpts) Algorithm() string {
	return IDEMIX
}

// Ephemeral returns true if the key to derive has to be ephemeral,
// false otherwise.
func (o *IdemixNymKeyDerivationOpts) Ephemeral() bool {
	return o.Temporary
}

// IssuerPublicKey returns the issuer public key used to derive
// a new unlinkable pseudonym from a credential secret key
func (o *IdemixNymKeyDerivationOpts) IssuerPublicKey() Key {
	return o.IssuerPK
}

// IdemixSignerOpts contains the options to generate an Idemix signature
type IdemixSignerOpts struct {
	// Nym is the pseudonym to be used
	Nym Key
	// IssuerPK is the public-key of the issuer
	IssuerPK Key
	// Credential is the byte representation of the credential signed by the issuer
	Credential []byte
	// Attributes specifies which attribute should be disclosed and which not.
	// If Attributes[i].Type = IdemixHiddenAttribute
	// then the i-th credential attribute should not be disclosed, otherwise the i-th
	// credential attribute will be disclosed.
	// At verification time, if the i-th attribute is disclosed (Attributes[i].Type != IdemixHiddenAttribute),
	// then Attributes[i].Value must be set accordingly.
	Attributes []IdemixAttribute
	// RhIndex is the index of attribute containing the revocation handler.
	// Notice that this attributed cannot be discloused
	RhIndex int
	// EidIndex contains the index of the EID attrbiute
	EidIndex int
	// CRI contains the credential revocation information
	CRI []byte
	// Epoch is the revocation epoch the signature should be produced against
	Epoch int
	// RevocationPublicKey is the revocation public key
	RevocationPublicKey Key
	// H is the hash function to be used
	H crypto.Hash
	// SigType is the type of signature that shall be generated
	SigType SignatureType
	// IdemixSignerMetadata contains metadata about the signature
	Metadata *IdemixSignerMetadata
	// VerificationType controls what type of verification the caller expects
	VerificationType VerificationType
}

func (o *IdemixSignerOpts) HashFunc() crypto.Hash {
	return o.H
}

type EidNymAuditOpts struct {
	EidIndex     int
	EnrollmentID string
	RNymEid      *mathlib.Zr
}

func (o *EidNymAuditOpts) HashFunc() crypto.Hash {
	return 0
}

// IdemixCRISignerOpts contains the options to generate an Idemix CRI.
// The CRI is supposed to be generated by the Issuing authority and
// can be verified publicly by using the revocation public key.
type IdemixCRISignerOpts struct {
	Epoch               int
	RevocationAlgorithm RevocationAlgorithm
	UnrevokedHandles    [][]byte
	// H is the hash function to be used
	H crypto.Hash
}

func (o *IdemixCRISignerOpts) HashFunc() crypto.Hash {
	return o.H
}

const (
	// Standard is the base signature type
	Standard SignatureType = iota
	// EidNym adds a hiding and binding commitment to the enrollment id and proves its correctness
	EidNym
)

const (
	// Basic performs the verification without any of the extensions (e.g. it ignores the nym eid)
	Basic VerificationType = iota
	// BestEffort performs all verifications possible given the available information in the signature/opts
	BestEffort
	// ExpectStandard expects a SignatureType of type Standard
	ExpectStandard
	// ExpectEidNym expects a SignatureType of type EidNym
	ExpectEidNym
)

const (
	// IdemixHiddenAttribute represents an hidden attribute
	IdemixHiddenAttribute IdemixAttributeType = iota
	// IdemixStringAttribute represents a sequence of bytes
	IdemixBytesAttribute
	// IdemixIntAttribute represents an int
	IdemixIntAttribute
)

// IdemixUserSecretKeyGenOpts contains the options for the generation of an Idemix credential secret key.
type IdemixUserSecretKeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (*IdemixUserSecretKeyGenOpts) Algorithm() string {
	return IDEMIX
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (o *IdemixUserSecretKeyGenOpts) Ephemeral() bool {
	return o.Temporary
}

// IdemixRevocationKeyGenOpts contains the options for the Idemix revocation key-generation.
type IdemixRevocationKeyGenOpts struct {
	// Temporary tells if the key is ephemeral
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (*IdemixRevocationKeyGenOpts) Algorithm() string {
	return IDEMIX
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (o *IdemixRevocationKeyGenOpts) Ephemeral() bool {
	return o.Temporary
}

// IdemixRevocationPublicKeyImportOpts contains the options for importing of an Idemix revocation public key.
type IdemixRevocationPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (*IdemixRevocationPublicKeyImportOpts) Algorithm() string {
	return IDEMIX
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (o *IdemixRevocationPublicKeyImportOpts) Ephemeral() bool {
	return o.Temporary
}

// IdemixRevocationKeyImportOpts contains the options for importing of an Idemix revocation key pair.
type IdemixRevocationKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (*IdemixRevocationKeyImportOpts) Algorithm() string {
	return IDEMIX
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (o *IdemixRevocationKeyImportOpts) Ephemeral() bool {
	return o.Temporary
}

// IdemixNymKeyImportOpts contains the options to import a pseudonym
type IdemixNymKeyImportOpts struct {
	// Temporary tells if the key is ephemeral
	Temporary bool
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (*IdemixNymKeyImportOpts) Algorithm() string {
	return IDEMIX
}

// Ephemeral returns true if the key to derive has to be ephemeral,
// false otherwise.
func (o *IdemixNymKeyImportOpts) Ephemeral() bool {
	return o.Temporary
}

// IdemixNymPublicKeyImportOpts contains the options to import the public part of a pseudonym
type IdemixNymPublicKeyImportOpts struct {
	// Temporary tells if the key is ephemeral
	Temporary bool
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (*IdemixNymPublicKeyImportOpts) Algorithm() string {
	return IDEMIX
}

// Ephemeral returns true if the key to derive has to be ephemeral,
// false otherwise.
func (o *IdemixNymPublicKeyImportOpts) Ephemeral() bool {
	return o.Temporary
}

// IdemixUserSecretKeyImportOpts contains the options for importing of an Idemix credential secret key.
type IdemixUserSecretKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (*IdemixUserSecretKeyImportOpts) Algorithm() string {
	return IDEMIX
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (o *IdemixUserSecretKeyImportOpts) Ephemeral() bool {
	return o.Temporary
}
