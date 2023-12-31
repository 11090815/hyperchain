package msp

import (
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
)

var mspLogger = hlogging.MustGetLogger("msp")

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type MSPVersion int

const (
	MSPv1_0 = iota
	MSPv1_1
	MSPv1_3
	MSPv1_4_3
)

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type Identity interface {
	// ExpiresAt 返回个人信息的过期时间。
	ExpiresAt() time.Time

	// GetIdentifier 返回身份标识符。
	GetIdentifier() *IdentityIdentifier

	// GetMSPIdentifier 返回 MSP 的身份标识符。
	GetMSPIdentifier() string

	// Validate 验证身份证书是否被撤销。
	Validate() error

	// GetOrganizationalUnits 返回与此身份关联的零个或多个组织单位。
	GetOrganizationalUnits() []*OUIdentifier

	// Anonymous 返回此身份是否是匿名身份。
	Anonymous() bool

	// Verify 使用此身份验证某个消息上的签名。
	Verify(msg []byte, sig []byte) error

	// Serialize 将身份信息序列化成字节。
	Serialize() ([]byte, error)

	// SatisfiesPrincipal 检查该实例是否与 MSPPrincipal 中提供的描述相匹配。
	// 检查可能涉及逐字节比较（如果 principal 被序列化的身份标识），也可能需要 MSP 验证。
	SatisfiesPrincipal(principal *pbmsp.MSPPrincipal) error
}

type SigningIdentity interface {
	Identity

	// Sign 给消息签名。
	Sign(msg []byte) ([]byte, error)

	// GetPublicVersion 返回该身份的公开部分。
	GetPublicVersion() Identity
}

type IdentityDeserializer interface {
	// DeserializeIdentity 返序列化身份信息，提取身份信息中的证书信息，然后基于证书信息构建 Identity，并将
	// 构建的 Identity 返回出来。
	DeserializeIdentity(serializedIdentity []byte) (Identity, error)

	// IsWellFormed 检查身份信息的证书部分内容，证书部分内容是以 ASN.1 DER PEM 格式组织的，首先就是检查利用
	// pem.Decode() 方法得到的 pem.Block 是否正常，并且 rest 部分应当是空的，其次就是解析 pem.Block.Bytes
	// 能否被顺利解析成 x509.Certificate，能得话，提供的 pbmsp.SerializedIdentity 的格式就是正确的。
	IsWellFormed(identity *pbmsp.SerializedIdentity) error
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type MSP interface {
	IdentityDeserializer

	// Setup 配置 MSP。
	Setup(config *pbmsp.MSPConfig) error

	GetIdentifier() string

	GetDefaultSigningIdentity() (SigningIdentity, error)

	GetTLSRootCerts() [][]byte

	GetTLSIntermediateCerts() [][]byte

	Validate(id Identity) error

	SatisfiesPrincipal(id Identity, principal *pbmsp.MSPPrincipal) error
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type MSPManager interface {
	IdentityDeserializer
	Setup(msps []MSP) error
	GetMSPs() map[string]MSP
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type OUIdentifier struct {
	// CertifiersIdentifier 与该组织单位关联的证书信任链的哈希值。
	CertifiersIdentifier []byte

	// OrganizationalUnitIdentifier 定义了用 MSPIdentifier 标识的 MSP 下的组织单位。
	OrganizationalUnitIdentifier string
}
