package msp

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"time"

	"github.com/11090815/hyperchain/bccsp"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
	"github.com/11090815/hyperchain/vars"
	"google.golang.org/protobuf/proto"
)

var (
	//  Subject Alternative Name，缩写为 SAN。它可以包括一个或者多个的电子邮件地址，域名，IP地址和 URI 等。
	oidExtensionSubjectAltName  = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}
)

type mspSetupFuncType func(config *pbmsp.HyperchainMSPConfig) error

type validateIdentityOUsFuncType func(id *identity) error

type satisfiesPrincipalInternalFuncType func(id Identity, principal *pbmsp.MSPPrincipal) error

type setupAdminInternalFuncType func(conf *pbmsp.HyperchainMSPConfig) error

type bccspmsp struct {
	// version 规范了 MSP 的行为。
	version MSPVersion

	// internalSetupFunc 根据版本改变 MSP 的行为。
	internalSetupFunc mspSetupFuncType

	// internalValidateIdentityOUsFunc 验证身份的组织单位。
	internalValidateIdentityOUsFunc validateIdentityOUsFuncType

	// internalSatisfiesPrincipalInternalFunc 检查是否满足 principal。
	internalSatisfiesPrincipalInternalFunc satisfiesPrincipalInternalFuncType

	// internalSetupAdmin 为 MSP 设置管理员。
	internalSetupAdminsFunc setupAdminInternalFuncType

	// rootCerts CA 证书。
	rootCerts []Identity

	// intermediateCerts 中级证书。
	intermediateCerts []Identity

	// tlsRootCerts CA 的 TLS 证书。
	tlsRootCerts [][]byte

	// tlsIntermediateCerts 中级 TLS 证书。
	tlsIntermediateCerts [][]byte

	// certificationTreeInternalNodesMap 的键对应于转换成字符串的证书原始资料（DER），
	// 其值为布尔值。true 表示证书是证书树的内部节点。false 表示证书是证书树的叶子。
	// intermediateCerts 里的每个中级身份证书被单拎出来，然后解析每个证书的证书链，将证书链中的父辈证书全都
	// 记录到 certificationTreeInternalNodesMap 中。
	certificationTreeInternalNodesMap map[string]bool

	signer SigningIdentity

	// admins 管理员列表。
	admins []Identity

	// csp 提供密码服务。
	csp bccsp.BCCSP

	// name MSP 的名字。
	name string

	// opts 验证成员证书的选项。
	opts *x509.VerifyOptions

	// RLs 若干个证书撤销列表，每个撤销列表里存放的撤销的证书都由同一个 Issuer (CA) 发布。
	RLs []*x509.RevocationList

	// ouIdentifiers 组织单位列表
	ouIdentifiers map[string][][]byte

	cryptoConfig *pbmsp.HyperchainCryptoConfig

	ouEnforcement bool

	clientOU, peerOU, adminOU, ordererOU *OUIdentifier
}

// IsWellFormed 给定参数 *pbmsp.SerializedIdentity，按照以下步骤检查 SerializedIdentity.IdBytes 是否合法：
//  1. 利用 pem.Decode 对其进行解码，看看得到的 block 是否不为 nil，然后看看得到的 rest 是否为 nil；
//  2. 检查得到的 block.Type 是否为 "CERTIFICATE" 或者 ""；
//  3. 接着利用 x509.ParseCertificate 解析 block.Bytes，看看是否有错误；
//  4. 最后，如果解析得到的 x509 证书是利用 ECDSA 算法签署的，检查其中签名的形式是否正确（并非利用公钥检查签名的合法性）。
func (msp *bccspmsp) IsWellFormed(identity *pbmsp.SerializedIdentity) error {
	block, rest := pem.Decode(identity.IdBytes)
	if block == nil {
		return fmt.Errorf("invalid identity [%s], get empty block", identity.IdBytes)
	}
	if len(rest) > 0 {
		return fmt.Errorf("invalid identity [%s], get non-empty rest", identity.IdBytes)
	}

	if block.Type != "CERTIFICATE" && block.Type != "" {
		return fmt.Errorf("the type of PEM should be \"CERTIFICATE\" or \"\", shouldn't be [%s]", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	if !isECDSASignedCert(cert) {
		return nil
	}

	return isIdentitySignedInCanonicalForm(cert.Signature, identity.Mspid, identity.IdBytes)
}

// SatisfiesPrincipal 调用 internalSatisfiesPrincipalInternalFunc 方法验证 principal。
func (msp *bccspmsp) SatisfiesPrincipal(id Identity, principal *pbmsp.MSPPrincipal) error {
	principals, err := collectPrincipals(principal, msp.GetVersion())
	if err != nil {
		return err
	}
	for _, p := range principals {
		if err = msp.internalSatisfiesPrincipalInternalFunc(id, p); err != nil {
			return err
		}
	}
	return nil
}

func (msp *bccspmsp) GetVersion() MSPVersion {
	return msp.version
}

func (msp *bccspmsp) GetType() ProviderType {
	return HYPERCHAIN
}

// GetIdentifier 返回 msp 的名字。
func (msp *bccspmsp) GetIdentifier() string {
	return msp.name
}

// GetTLSRootCerts 返回 TLS 连接配置中的根证书。
func (msp *bccspmsp) GetTLSRootCerts() [][]byte {
	return msp.tlsRootCerts
}

func (msp *bccspmsp) GetTLSIntermediateCerts() [][]byte {
	return msp.tlsIntermediateCerts
}

func (msp *bccspmsp) GetDefaultSigningIdentity() (SigningIdentity, error) {
	if msp.signer == nil {
		return nil, errors.New("this msp does not possess a valid default signing identity")
	}

	return msp.signer, nil
}

// Validate 传入的参数必须是 *identity 的实例，然后调用 msp.validateIdentity() 方法验证 *identity 的正确性。
//
// validateIdentity: 给定一个身份 *identity，调用 getCertificateChainForBCCSPIdentity 方法，
// 获取该证书的验证链，验证链中的第二个整数是给定身份中的证书的签发者，检查 msp 本地证书撤销列表，
// 是否存在由该签发者签发的证书撤销列表，如果有的话，检查该列表中是否含有该身份所指向的证书，如果
// 有的话，则说明该身份是被撤销的，不合法，否则继续进行其他步骤的验证。
func (msp *bccspmsp) Validate(id Identity) error {
	switch id := id.(type) {
	case *identity:
		return msp.validateIdentity(id)
	default:
		return fmt.Errorf("identity type [%T] not recognized", id)
	}
}

func (msp *bccspmsp) Setup(c *pbmsp.MSPConfig) error {
	if c == nil {
		return vars.ErrorShouldNotBeNil{Type: reflect.TypeOf(c)}
	}

	conf := &pbmsp.HyperchainMSPConfig{}
	if err := proto.Unmarshal(c.Config, conf); err != nil {
		return err
	}

	msp.name = conf.Name
	mspLogger.Debugf("Setup MSP instance %s.", msp.name)

	return msp.internalSetupFunc(conf)
}

// DeserializeIdentity 给定 protobuf 序列化后的 Identity，先利用 proto.Unmarshal() 方法对其进行反序列化，得到 &pbmsp.SerializedIdentity{}，
// pbmsp.SerializedIdentity.IdBytes 是 x509 证书的 ASN.1 DER PEM 格式编码的数据，然后根据 pbmsp.SerializedIdentity.IdBytes 解析得到一个
// Identity。
func (msp *bccspmsp) DeserializeIdentity(serializedID []byte) (Identity, error) {
	sid := &pbmsp.SerializedIdentity{}
	if err := proto.Unmarshal(serializedID, sid); err != nil {
		return nil, err
	}

	if sid.Mspid != msp.name {
		return nil, fmt.Errorf("expected msp id [%s], but got [%s]", msp.name, sid.Mspid)
	}

	return msp.deserializeIdentityInternal(sid.IdBytes)
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

// satisfiesPrincipalInternalPreV13 验证身份的逻辑如下：
//
//  1. 如果给定的 principal.PrincipalClassification 等于 pbmsp.MSPPrincipal_ROLE：将 principal.Principal 反序列化成 &pbmsp.MSPRole{} 后，按照以下顺序验证：
//
//     1.1 如果 mspRole.Role = pbmsp.MSPRole_MEMBER，则验证给定的 Identity 是否被正确签发、是否被撤销、Identity 的组织是否正确；
//
//     1.2 如果 mspRole.Role = pbmsp.MSPRole_ADMIN，则判断给定的 Identity 是否在 msp 的管理员列表中；
//
//     1.3 如果 mspRole.Role = pbmsp.MSPRole_CLIENT，则按照 mspRole.Role = pbmsp.MSPRole_PEER 时的情况验证给定的 Identity；
//
//     1.4 如果 mspRole.Role = pbmsp.MSPRole_PEER，则验证给定的 Identity 是否被正确签发、是否被撤销、Identity 的组织是否正确，并检查给定的 Identity 是否属于与指定 MSPRole 关联的组织单位。
//
//     1.5 如果 mspRole.Role = 其他值，则报错。
//
//  2. 如果给定的 principal.PrincipalClassification 等于 pbmsp.MSPPrincipal_IDENTITY：利用 msp.DeserializeIdentity() 方法解析 principal.Principal 得到 Identity 实例 principalID：
//
//     2.1 验证解析得到的 principalID.(*identity).cert.Raw 和给定的 id.(*identity).cert.Raw 一不一样。
//
//  3. 如果给定的 principal.PrincipalClassification 等于 pbmsp.MSPPrincipal_ORGANIZATION_UNIT，将 principal.Principal 反序列化成一个 *pbmsp.OrganizationUnit 实例 ou 后，按照以下顺序进行验证：
//
//     3.1 判断 ou.MspIdentifier 与 msp.name 一不一样；
//
//     3.2 验证给定的 Identity 是否被正确签发、是否被撤销、Identity 的组织是否正确；
//
//     3.3 验证与给定 Identity 管理的组织是否与 ou 里的组织单元匹配，如果存在一个匹配，则验证通过。
//
//  4. 如果给定的 principal.PrincipalClassification 等于其他值，则直接报错。
func (msp *bccspmsp) satisfiesPrincipalInternalPreV13(id Identity, principal *pbmsp.MSPPrincipal) error {
	if _, ok := id.(*identity); !ok {
		return errors.New("invalid identity type, expected *identity")
	}

	switch principal.PrincipalClassification {
	case pbmsp.MSPPrincipal_ROLE: // msp principal 的分类是角色
		mspRole := &pbmsp.MSPRole{}
		if err := proto.Unmarshal(principal.Principal, mspRole); err != nil {
			return err
		}
		if mspRole.MspIdentifier != msp.name { // 角色的 msp 标识符必须与本 msp 的名字一样
			return fmt.Errorf("the identity is a member of a different msp [%s], expected msp is [%s]", mspRole.MspIdentifier, msp.name)
		}

		switch mspRole.Role {
		case pbmsp.MSPRole_MEMBER: // 成员角色
			mspLogger.Debugf("Checking if identity satisfies member role for msp [%s].", msp.name)
			return msp.Validate(id) // 验证身份是否被正确签发，验证身份是否被撤销，验证身份的组织是否正确
		case pbmsp.MSPRole_ADMIN: // 管理员角色
			mspLogger.Debugf("Checking if identity satisfies admin role for msp [%s].", msp.name)
			if msp.isInAdmin(id.(*identity)) { // 判断该身份是否在 msp 的管理员列表中
				return nil
			} else {
				return fmt.Errorf("identity [%s] is not an admin", id.(*identity).id.Id)
			}
		case pbmsp.MSPRole_CLIENT: // client 角色，直接进入验证 peer 角色的过程中
			fallthrough
		case pbmsp.MSPRole_PEER:
			mspLogger.Debugf("Checking if identity satisfies peer role for msp [%s].", msp.name)
			if err := msp.Validate(id); err != nil { // 验证身份是否被正确签发，验证身份是否被撤销，验证身份的组织是否正确
				return fmt.Errorf("the identity is not valid under this msp [%s]", msp.name)
			}
			if err := msp.hasOURole(id, mspRole.Role); err != nil {
				return fmt.Errorf("the identity is not a peer under this msp [%s]", msp.name)
			}
			return nil
		default:
			return fmt.Errorf("invalid msp role type [%d]", mspRole.Role)
		}
	case pbmsp.MSPPrincipal_IDENTITY:
		principalID, err := msp.DeserializeIdentity(principal.Principal)
		if err != nil {
			return err
		}
		if bytes.Equal(id.(*identity).cert.Raw, principalID.(*identity).cert.Raw) {
			return principalID.Validate()
		}
		return errors.New("the certificate pointed by identity is mismatch")
	case pbmsp.MSPPrincipal_ORGANIZATION_UNIT:
		ou := &pbmsp.OrganizationUnit{}
		if err := proto.Unmarshal(principal.Principal, ou); err != nil {
			return err
		}
		if ou.MspIdentifier != msp.name {
			return fmt.Errorf("the organizational unit is a member of a different msp [%s], expected msp is [%s]", ou.MspIdentifier, msp.name)
		}
		if err := msp.Validate(id); err != nil {
			return err
		}
		for _, oUnit := range id.GetOrganizationalUnits() {
			// 验证与给定身份管理的组织是否与 principal 里的组织单元匹配，如果存在一个匹配，则验证通过
			if oUnit.OrganizationalUnitIdentifier == ou.OrganizationalUnitIdentifier && bytes.Equal(oUnit.CertifiersIdentifier, ou.CertifiersIdentifier) {
				return nil
			}
		}
		return fmt.Errorf("the identity is not part of any organizational unit")
	default:
		return fmt.Errorf("invalid principal classification [%d]", principal.PrincipalClassification)
	}
}

func (msp *bccspmsp) satisfiesPrincipalInternalV13(id Identity, principal *pbmsp.MSPPrincipal) error {
	switch principal.PrincipalClassification {
	case pbmsp.MSPPrincipal_COMBINED:
		return errors.New("unsupport combined principal")
	case pbmsp.MSPPrincipal_ANONYMITY:
		anon := &pbmsp.MSPIdentityAnonymity{}
		if err := proto.Unmarshal(principal.Principal, anon); err != nil {
			return err
		}
		switch anon.AnonymityType {
		case pbmsp.MSPIdentityAnonymity_ANONYMOUS:
			return errors.New("principal is anonymous, but x.509 MSP does not support anonymous identities")
		case pbmsp.MSPIdentityAnonymity_NOMINAL: // 有名无实
			return nil
		default:
			return fmt.Errorf("unknown principal anonymity type: %d", anon.AnonymityType)
		}
	default:
		return msp.satisfiesPrincipalInternalPreV13(id, principal)
	}
}

func (msp *bccspmsp) satisfiesPrincipalInternalV142(id Identity, principal *pbmsp.MSPPrincipal) error {
	if _, ok := id.(*identity); !ok {
		return errors.New("invalid identity type, expected *identity")
	}

	switch principal.PrincipalClassification {
	case pbmsp.MSPPrincipal_ROLE:
		if !msp.ouEnforcement {
			break
		}
		mspRole := &pbmsp.MSPRole{}
		if err := proto.Unmarshal(principal.Principal, mspRole); err != nil {
			return err
		}
		if mspRole.MspIdentifier != msp.name {
			return fmt.Errorf("the identity is a member of a different msp [%s], expected msp is [%s]", mspRole.MspIdentifier, msp.name)
		}

		switch mspRole.Role {
		case pbmsp.MSPRole_ADMIN:
			mspLogger.Debugf("Checking if identity satisfies admin role for msp [%s].", msp.name)
			if msp.isInAdmin(id.(*identity)) { // 判断该身份是否在 msp 的管理员列表中
				return nil
			}

			mspLogger.Debugf("Checking if identity carries the admin ou for %s.", msp.name)
			if err := msp.Validate(id); err != nil {
				return err
			}
			if err := msp.hasOURole(id, pbmsp.MSPRole_ADMIN); err != nil {
				return err
			}
			return nil
		case pbmsp.MSPRole_ORDERER:
			mspLogger.Debugf("Checking if identity satisfies orderer role for msp [%s].", msp.name)
			if err := msp.Validate(id); err != nil {
				return err
			}
			if err := msp.hasOURole(id, pbmsp.MSPRole_ORDERER); err != nil {
				return err
			}
			return nil
		}
	}

	return msp.satisfiesPrincipalInternalV13(id, principal)
}

// isInAdmin 判断给定的身份是否在 msp 的管理员列表中。
func (msp *bccspmsp) isInAdmin(id *identity) bool {
	for _, adminIdentity := range msp.admins {
		if bytes.Equal(id.cert.Raw, adminIdentity.(*identity).cert.Raw) {
			return true
		}
	}
	return false
}

// getIdentityFromConf 给定某个身份的 x509 证书的 ASN.1 DER PEM 编码的数据，然后从该证书中提取出以下信息：
//  1. x509.Certificate
//  2. bccsp.Key (公钥)
//  3. 16 进制的身份标识符字符串
//
// 根据以上信息构建 *identity。
func (msp *bccspmsp) getIdentityFromConf(certPEM []byte) (Identity, bccsp.Key, error) {
	cert, err := getCertFromPEM(certPEM)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := msp.csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, nil, err
	}

	id, err := newIdentity(cert, publicKey, msp)
	if err != nil {
		return nil, nil, err
	}
	return id, publicKey, nil
}

// getSigningIdentityFromConf 给定的 *pbmsp.SigningIdentityInfo 实例中含有 signing identity 的公钥和私钥信息，公钥信息是 ASN.1 DER PEM 编码
// 的 x509 证书，根据它解析得到 bccsp 里定义的 ecdsa 公钥，然后尝试利用 bccsp 的 GetKey 方法，通过公钥的 SKI 从 KeyStore 中获取 signing identity
// 的私钥，如果获取失败，就根据 *pbmsp.SigningIdentityInfo 里的私钥信息，利用 bccsp 的 KeyImport 方法导出私钥。最后基于解析得来的证书、公钥、私钥
// 和当前状态的 msp 新建一个 signing identity。
func (msp *bccspmsp) getSigningIdentityFromConf(sidInfo *pbmsp.SigningIdentityInfo) (SigningIdentity, error) {
	if sidInfo == nil {
		return nil, vars.ErrorShouldNotBeNil{Type: reflect.TypeOf(sidInfo)}
	}

	id, publicKey, err := msp.getIdentityFromConf(sidInfo.PublicSigner)
	if err != nil {
		return nil, err
	}

	privateKey, err := msp.csp.GetKey(publicKey.SKI())
	if err != nil {
		// KeyStore 里应该没有存储过该私钥，那么就转为密钥导入方法根据密钥信息导出密钥。
		if sidInfo.PrivateSigner == nil || sidInfo.PrivateSigner.KeyMaterial == nil {
			return nil, errors.New("key material not found in SigningIdentityInfo")
		}

		block, _ := pem.Decode(sidInfo.PrivateSigner.KeyMaterial)
		if block == nil {
			return nil, vars.ErrorDecodePEMFormatKey{BlockIsNil: true}
		}
		privateKey, err = msp.csp.KeyImport(block.Bytes, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: true})
		if err != nil {
			return nil, err
		}
	}

	signer, err := bccsp.NewCryptoSigner(msp.csp, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed getting signing identity: [%s]", err.Error())
	}

	return newSigningIdentity(id.(*identity).cert, publicKey, signer, msp)
}

// getValidityOptsForCert 的代码如下：
//
//	{
//		var opts x509.VerifyOptions
//		opts.Roots = msp.opts.Roots                   // *x509.CertPool
//		opts.DNSName = msp.opts.DNSName               // string
//		opts.Intermediates = msp.opts.Intermediates   // *x509.CertPool
//		opts.KeyUsages = msp.opts.KeyUsages           // []x509.ExtKeyUsage
//		opts.CurrentTime = notBefore.Add(time.Second) // time.Time 证书的起始时间
//		return opts
//	}
func (msp *bccspmsp) getValidityOptsForCert(notBefore time.Time) x509.VerifyOptions {
	var opts x509.VerifyOptions
	opts.Roots = msp.opts.Roots                   // *x509.CertPool
	opts.DNSName = msp.opts.DNSName               // string
	opts.Intermediates = msp.opts.Intermediates   // *x509.CertPool
	opts.KeyUsages = msp.opts.KeyUsages           // []x509.ExtKeyUsage
	opts.CurrentTime = notBefore.Add(time.Second) // time.Time 证书的起始时间

	return opts
}

// getValidationChain 调用 getUniqueValidationChain 方法返回验证链，检查验证链的长度是否不小于 2，小于 2 的话就代表最终实体证书是根 CA 证书，这是不允许的，
// 其次就是最终实体证书的父级证书是否是 MSP 的证书树中的内部节点，如果是的话，则也是不允许的。最后原封不动的返回验证链。
func (msp *bccspmsp) getValidationChain(cert *x509.Certificate, isIntermediateChain bool) ([]*x509.Certificate, error) {
	chain, err := msp.getUniqueValidationChain(cert, msp.getValidityOptsForCert(cert.NotBefore))
	if err != nil {
		return nil, fmt.Errorf("failed getting validation chain: [%s]", err.Error())
	}

	if len(chain) < 2 {
		// 我们需要这个证书不是根 CA 证书
		return nil, errors.New("expected a certificate chain of length at least 2")
	}

	parentPosition := 1
	if isIntermediateChain {
		parentPosition = 0
	}
	// 由于 certificationTreeInternalNodesMap 里注册的是 intermediateCerts 中所有中级身份证书的父辈证书节点，并没有注册 intermediateCerts 中
	// 的证书，因此，如果 cert 属于 intermediateCerts，即 isIntermediateChain 等于 true，那么证书链的第一个证书就不应该存在于 certificationTreeInternalNodesMap
	// 中，也就是当 parentPosition 等于 0 的情况下。另外，如果 cert 不属于 intermediateCerts，那么 cert 的父辈证书节点就不应该存在于 intermediateCerts
	// 中，因此，证书链里的第二个证书，也就是 cert 的第一级父辈证书就不应该存在于 certificationTreeInternalNodesMap 中。到此判断逻辑解释完毕。
	if msp.certificationTreeInternalNodesMap[string(chain[parentPosition].Raw)] {
		return nil, errors.New("invalid validation chain, parent certificate should be a leaf of certificate tree")
	}

	return chain, nil
}

func (msp *bccspmsp) getCertificateChainIdentifier(id Identity) ([]byte, error) {
	chain, err := msp.getCertificateChain(id)
	if err != nil {
		return nil, fmt.Errorf("failed getting certificate chain for [%v]: [%s]", id, err.Error())
	}

	return msp.getCertificateChainIdentifierFromChain(chain[1:])
}

// getCertificateChain 给定一个身份 Identity，Identity 是一个接口，如果该接口的本质是 *identity，那么在进行类型断言后，
// 直接调用 getCertificateChainForBCCSPIdentity 方法。注意：*identity 里的 x509 证书不能是 CA 证书，不然会报错。
func (msp *bccspmsp) getCertificateChain(id Identity) ([]*x509.Certificate, error) {
	switch id := id.(type) {
	case *identity:
		return msp.getCertificateChainForBCCSPIdentity(id)
	default:
		return nil, fmt.Errorf("identity type [%T] not recognized", id)
	}
}

// getCertificateChainForBCCSPIdentity 给定一个身份 *identity，该身份结构中含有一个 x509 证书实例，在该证书实例不是 CA 证书的情况下，获取该证书的验证链。
// 因为 CA 证书不适合拿来作为一个身份，一般来说 CA 证书是需要被隐藏起来的。
func (msp *bccspmsp) getCertificateChainForBCCSPIdentity(id *identity) ([]*x509.Certificate, error) {
	if id == nil {
		return nil, errors.New("invalid bccsp identity, it must be not nil")
	}

	if msp.opts == nil {
		return nil, errors.New("invalid msp instance, it must provide VerifyOptions instance")
	}

	if id.cert.IsCA {
		return nil, errors.New("a certificate of CA cannot be used as an identity")
	}

	return msp.getValidationChain(id.cert, false)
}

// getCertificateChainIdentifierFromChain 给定一个证书链，计算该证书链的 SHA256 哈希值。
func (msp *bccspmsp) getCertificateChainIdentifierFromChain(chain []*x509.Certificate) ([]byte, error) {
	hash, err := msp.csp.GetHash(&bccsp.SHA256Opts{})
	if err != nil {
		return nil, fmt.Errorf("failed getting hash function when computing certification chain identifier")
	}
	for i := 0; i < len(chain); i++ {
		hash.Write(chain[i].Raw)
	}

	return hash.Sum(nil), nil
}

// santizeCert 什么也没做。
//
// Deprecated: FISCO BCOS 里解释了为什么要净化证书，但是我不想净化。
func (msp *bccspmsp) santizeCert(cert *x509.Certificate) (*x509.Certificate, error) {
	return cert, nil
}

func (msp *bccspmsp) getUniqueValidationChain(cert *x509.Certificate, opts x509.VerifyOptions) ([]*x509.Certificate, error) {
	// 验证证书后获得若干条证书链，我们在这里只希望获得一条证书链。提供的选项参数需要提供以下信息：
	// 	- Roots：存放根 CA 证书的证书池
	//	- DNSName：可选项，可填可不填
	//	- Intermediates：存放中级证书的证书池，这里要求要把证书信任链上的所有中级证书都添加进来，否则 Verify 方法会报错
	//	- KeyUsages：不知道的情况下，就填 []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	chains, err := cert.Verify(opts)
	if err != nil {
		return nil, err
	}

	if len(chains) != 1 {
		return nil, fmt.Errorf("this MSP only supports a single validation chain, got [%d]", len(chains))
	}

	if err = verifyLegacyNameConstraints(chains[0]); err != nil {
		return nil, fmt.Errorf("the supplied identity is not valid")
	}

	return chains[0], nil
}

// validateIdentity 给定一个身份 *identity，调用 getCertificateChainForBCCSPIdentity 方法，
// 获取该证书的验证链，验证链中的第二个证书是给定身份中的证书的签发者，检查 msp 本地证书撤销列表，
// 是否存在由该签发者签发的证书撤销列表，如果有的话，检查该列表中是否含有该身份所指向的证书，如果
// 有的话，则说明该身份是被撤销的，不合法，否则继续进行其他步骤的验证。
func (msp *bccspmsp) validateIdentity(id *identity) error {
	id.validationMutex.Lock()
	defer id.validationMutex.Unlock()

	if id.validated {
		// 已经验证过了
		return id.validationErr
	}

	id.validated = true

	validationChain, err := msp.getCertificateChainForBCCSPIdentity(id)
	if err != nil {
		id.validationErr = fmt.Errorf("could not obtain certificate chain: [%s]", err.Error())
		return id.validationErr
	}

	// 检查证书是否已被撤销，如果撤销，返回一个非空错误。
	if err = msp.validateIdentityAgainstChain(id, validationChain); err != nil {
		id.validationErr = fmt.Errorf("could not validate identity against certificate chain: [%s]", err.Error())
		return id.validationErr
	}

	if err = msp.internalValidateIdentityOUsFunc(id); err != nil {
		id.validationErr = fmt.Errorf("could not validate identity's OUs: [%s]", err.Error())
		return id.validationErr
	}

	return nil
}

func (msp *bccspmsp) validateIdentityAgainstChain(id *identity, validationChain []*x509.Certificate) error {
	return msp.validateCertAgainstChain(id.cert, validationChain)
}

func (msp *bccspmsp) validateCAIdentity(id *identity) error {
	if !id.cert.IsCA {
		return fmt.Errorf("certificate [sn:%s] is belong to CA, but it didn't have CA attribute", id.cert.SerialNumber)
	}
	validationChain, err := msp.getUniqueValidationChain(id.cert, msp.getValidityOptsForCert(id.cert.NotBefore))
	if err != nil {
		return err
	}
	if len(validationChain) == 1 {
		// 根 CA 证书
		return nil
	}
	return msp.validateCertAgainstChain(id.cert, validationChain)
}

func (msp *bccspmsp) validateTLSCAIdentity(cert *x509.Certificate, opts *x509.VerifyOptions) error {
	if !cert.IsCA {
		return fmt.Errorf("certificate [sn:%s] is belong to CA, but it didn't have CA attribute", cert.SerialNumber.String())
	}

	validationChain, err := msp.getUniqueValidationChain(cert, *opts)
	if err != nil {
		return err
	}

	if len(validationChain) == 1 {
		return nil
	}

	return msp.validateCertAgainstChain(cert, validationChain)
}

func (msp *bccspmsp) validateCertAgainstChain(cert *x509.Certificate, validationChain []*x509.Certificate) error {
	// 1. 获取签署待验证证书的 CA 的 SKI 标识符。
	ski, err := getSKIFromCert(validationChain[1])
	if err != nil {
		return fmt.Errorf("cannot obtain subject key identifier from the certificate of the signer")
	}

	for _, rl := range msp.RLs {
		aki, err := getAKIFromCert(rl)
		if err != nil {
			return fmt.Errorf("could not obtain authority identifier from the certificate revocation list: [%s]", err.Error())
		}

		if bytes.Equal(aki, ski) {
			// 证书撤销列表 AKI 与 CA 证书的 SKI 一致，说明此撤销列表里的证书可能由该 CA 证书发布。
			for _, rc := range rl.RevokedCertificates {
				if rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					// 如果撤销列表里的某个证书的序列号与待验证的证书序列号一样，那么待验证的证书已经被加入到撤销列表中了，
					// 继续检查该撤销了表是否由 CA 发布的，如果是的话，则可以确定该证书已经被撤销了。
					if err = rl.CheckSignatureFrom(validationChain[1]); err != nil {
						mspLogger.Warnf("Invalid signature over the identified CRL :[%s].", err.Error())
						continue
					}

					return errors.New("the certificate has been revoked")
				}
			}
		}
	}

	return nil
}

// hasOURole 检查给定的身份是否属于与指定 MSPRole 关联的组织单位。
func (msp *bccspmsp) hasOURole(id Identity, mspRole pbmsp.MSPRole_MSPRoleType) error {
	if !msp.ouEnforcement {
		return errors.New("NodeOUs is not activated, cannot tell apart identities")
	}

	switch id := id.(type) {
	case *identity:
		return msp.hasOURoleInternal(id, mspRole)
	default:
		return fmt.Errorf("identity type [%T] not recognized", id)
	}
}

// hasOURoleInternal 判断给定的身份是否含有给定的 msp role 对应的组织单元标识符。
func (msp *bccspmsp) hasOURoleInternal(id *identity, mspRole pbmsp.MSPRole_MSPRoleType) error {
	var nodeOU *OUIdentifier
	switch mspRole {
	case pbmsp.MSPRole_ADMIN:
		nodeOU = msp.adminOU
	case pbmsp.MSPRole_CLIENT:
		nodeOU = msp.clientOU
	case pbmsp.MSPRole_ORDERER:
		nodeOU = msp.ordererOU
	case pbmsp.MSPRole_PEER:
		nodeOU = msp.peerOU
	default:
		return errors.New("invalid MSPRoleType. It must be CLIENT, PEER, ADMIN or ORDERER")
	}

	if nodeOU == nil {
		return fmt.Errorf("cannot test for classification, node ou for role [%s], not defined, msp: [%s]", mspRole, msp.name)
	}

	for _, ou := range id.GetOrganizationalUnits() {
		if ou.OrganizationalUnitIdentifier == nodeOU.OrganizationalUnitIdentifier {
			return nil
		}
	}

	return fmt.Errorf("the identity does not contain ou role [%s], msp: [%s]", mspRole, msp.name)
}

// deserializeIdentityInternal 给定身份证书的 ASN.1 DER PEM 格式编码的内容，然后解析成 x509 证书实例，再利用 bccsp 的
// KeyImport 导入 x509 证书，得到公钥，然后基于证书、公钥和当前的 msp 实例生成一个 Identity 实例。
func (msp *bccspmsp) deserializeIdentityInternal(serializedIdentity []byte) (Identity, error) {
	block, _ := pem.Decode(serializedIdentity)
	if block == nil {
		return nil, vars.ErrorDecodePEMFormatCertificate{BlockIsNil: true}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	pk, err := msp.csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, err
	}

	return newIdentity(cert, pk, msp)
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/
// setup 里的内容

// getCertifiersIdentifier 给定一个证书的 ASN.1 DER PEM 格式编码的数据，将其解析成 *x509.Certificate，
// 判断该证书是否被注册在本 msp 的 root 和 intermediate 证书列表中，没有的话会返回错误提示。随后获取该证书
// 的证书链，计算该证书链的 SHA256 哈希值，并将哈希值返回出来。
func (msp *bccspmsp) getCertifiersIdentifier(certRaw []byte) ([]byte, error) {
	// 1. 确保证书被 msp 注册为 root 或者 intermediate 证书
	cert, err := getCertFromPEM(certRaw)
	if err != nil {
		return nil, err
	}

	cert, _ = msp.santizeCert(cert)

	var (
		found = false
		root  = false
	)

	for _, rootCert := range msp.rootCerts {
		if rootCert.(*identity).cert.Equal(cert) {
			found = true
			root = true
			break
		}
	}

	if !found {
		for _, intermediateCert := range msp.intermediateCerts {
			if intermediateCert.(*identity).cert.Equal(cert) {
				found = true
				break
			}
		}
	}

	if !found {
		return nil, fmt.Errorf("certificate [%v] not in root or intermediate certs", cert)
	}

	// 2. 获取证书验证链
	var (
		certifiersIdentifier []byte
		chain                []*x509.Certificate
	)

	if root {
		chain = []*x509.Certificate{cert}
	} else {
		// cert 是一个中级证书
		chain, err = msp.getValidationChain(cert, true)
		if err != nil {
			return nil, err
		}
	}

	// 3. 计算验证链的 SHA256 哈希值
	certifiersIdentifier, err = msp.getCertificateChainIdentifierFromChain(chain)
	if err != nil {
		return nil, err
	}

	return certifiersIdentifier, nil
}

// setupCrypto 设置本 msp 采用的哈希算法，目前仅支持 SHA256 哈希算法。
func (msp *bccspmsp) setupCrypto(conf *pbmsp.HyperchainMSPConfig) error {
	msp.cryptoConfig = conf.CryptoConfig
	if msp.cryptoConfig == nil {
		msp.cryptoConfig = &pbmsp.HyperchainCryptoConfig{
			HashAlgorithm: bccsp.SHA256,
		}
		mspLogger.Debug("Crypto config is nil, switch to SHA256 (default).")
	}

	if msp.cryptoConfig.HashAlgorithm == "" {
		msp.cryptoConfig.HashAlgorithm = bccsp.SHA256
		mspLogger.Debug("Hash algorithm is not specified, switch to SHA256 (default).")
	}

	return nil
}

// setupCAs 给定一个 *pbmsp.HyperchainMSPConfig 实例，根据其中的 RootCerts 和 IntermediateCerts
// 设置 msp 的 CA 证书和中级证书：msp.rootCerts 和 msp.intermediateCerts。验证证书获取证书链的时候，
// 需要 x509.VerifyOptions 选项的参与，RootCerts 和 IntermediateCerts 可以构建选项中的根证书和中级
// 证书。
func (msp *bccspmsp) setupCAs(conf *pbmsp.HyperchainMSPConfig) error {
	if len(conf.RootCerts) == 0 {
		return errors.New("expected at least 1 CA certificate")
	}

	msp.opts = &x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}

	msp.rootCerts = make([]Identity, len(conf.RootCerts))
	for i, rootCert := range conf.RootCerts {
		id, _, err := msp.getIdentityFromConf(rootCert)
		if err != nil {
			return err
		}
		msp.rootCerts[i] = id
		msp.opts.Roots.AddCert(id.(*identity).cert)
	}

	msp.intermediateCerts = make([]Identity, len(conf.IntermediateCerts))
	for i, intermediateCert := range conf.IntermediateCerts {
		id, _, err := msp.getIdentityFromConf(intermediateCert)
		if err != nil {
			return err
		}
		msp.intermediateCerts[i] = id
		msp.opts.Intermediates.AddCert(id.(*identity).cert)
	}
	return nil
}

// finalizeSetupCAs 验证每个根 ca 和中级 ca 的合法性，并将每个中级证书的父辈证书注册到 certificationTreeInternalNodesMap 中。
func (msp *bccspmsp) finalizeSetupCAs() error {
	cas := append(append([]Identity{}, msp.rootCerts...), msp.intermediateCerts...)

	for _, caID := range cas {
		if _, err := getSKIFromCert(caID.(*identity).cert); err != nil {
			return err
		}
		if err := msp.validateCAIdentity(caID.(*identity)); err != nil {
			return err
		}
	}

	msp.certificationTreeInternalNodesMap = make(map[string]bool)
	for _, id := range msp.intermediateCerts {
		chain, err := msp.getUniqueValidationChain(id.(*identity).cert, msp.getValidityOptsForCert(id.(*identity).cert.NotBefore))
		if err != nil {
			return err
		}

		for i := 1; i < len(chain); i++ {
			msp.certificationTreeInternalNodesMap[string(chain[i].Raw)] = true
		}
	}

	return nil
}

func (msp *bccspmsp) setupAdmins(conf *pbmsp.HyperchainMSPConfig) error {
	return msp.internalSetupAdminsFunc(conf)
}

func (msp *bccspmsp) setupAdminsPreV142(conf *pbmsp.HyperchainMSPConfig) error {
	msp.admins = make([]Identity, len(conf.Admins))
	for i, adminCert := range conf.Admins {
		id, _, err := msp.getIdentityFromConf(adminCert)
		if err != nil {
			return err
		}
		msp.admins[i] = id
	}
	return nil
}

func (msp *bccspmsp) setupAdminsV142(conf *pbmsp.HyperchainMSPConfig) error {
	if err := msp.setupAdminsPreV142(conf); err != nil {
		return nil
	}

	// 添加完配置文件里提供的管理员身份证书信息后，继续执行以下步骤：
	if len(msp.admins) == 0 && (!msp.ouEnforcement || msp.adminOU == nil) {
		return errors.New("administrators must be declared when no admin organizational unit classification is set")
	}

	return nil
}

func (msp *bccspmsp) setupRLs(conf *pbmsp.HyperchainMSPConfig) error {
	msp.RLs = make([]*x509.RevocationList, len(conf.RevocationList))
	for i, crlRaw := range conf.RevocationList {
		crl, err := x509.ParseRevocationList(crlRaw)
		if err != nil {
			return err
		}
		msp.RLs[i] = crl
	}

	return nil
}

func (msp *bccspmsp) setupNodeOUs(conf *pbmsp.HyperchainMSPConfig) error {
	if conf.HyperchainNodeOus == nil {
		msp.ouEnforcement = false
	} else {
		msp.ouEnforcement = conf.HyperchainNodeOus.Enable

		if conf.HyperchainNodeOus.ClientOuIdentifier == nil || len(conf.HyperchainNodeOus.ClientOuIdentifier.OrganizationalUnitIdentifier) == 0 {
			return errors.New("failed setting up node ous, client ou must be non-nil")
		}

		if conf.HyperchainNodeOus.PeerOuIdentifier == nil || len(conf.HyperchainNodeOus.PeerOuIdentifier.OrganizationalUnitIdentifier) == 0 {
			return errors.New("failed setting up node ous, peer ou must be non-nil")
		}

		// client organizational unit
		msp.clientOU = &OUIdentifier{OrganizationalUnitIdentifier: conf.HyperchainNodeOus.ClientOuIdentifier.OrganizationalUnitIdentifier}
		if len(conf.HyperchainNodeOus.ClientOuIdentifier.Certificate) != 0 {
			// client organizational unit 的证书必须是在 msp 处注册过的 中级证书或者是根证书，一般来说是中级证书吧。
			certifiersIdentifier, err := msp.getCertifiersIdentifier(conf.HyperchainNodeOus.ClientOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			msp.clientOU.CertifiersIdentifier = certifiersIdentifier
		}

		// peer organizational unit
		msp.peerOU = &OUIdentifier{OrganizationalUnitIdentifier: conf.HyperchainNodeOus.PeerOuIdentifier.OrganizationalUnitIdentifier}
		if len(conf.HyperchainNodeOus.PeerOuIdentifier.Certificate) != 0 {
			// peer organizational unit 的证书必须是在 msp 处注册过的 中级证书或者是根证书，一般来说是中级证书吧。
			certifiersIdentifier, err := msp.getCertifiersIdentifier(conf.HyperchainNodeOus.PeerOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			msp.peerOU.CertifiersIdentifier = certifiersIdentifier
		}
	}

	return nil
}

func (msp *bccspmsp) setupNodeOUsV142(conf *pbmsp.HyperchainMSPConfig) error {
	if conf.HyperchainNodeOus == nil {
		msp.ouEnforcement = false
	} else {
		msp.ouEnforcement = conf.HyperchainNodeOus.Enable
		counter := 0

		// client organizational unit
		if conf.HyperchainNodeOus.ClientOuIdentifier != nil {
			msp.clientOU = &OUIdentifier{OrganizationalUnitIdentifier: conf.HyperchainNodeOus.ClientOuIdentifier.OrganizationalUnitIdentifier}
			if len(conf.HyperchainNodeOus.ClientOuIdentifier.Certificate) != 0 {
				certifiersIdentifier, err := msp.getCertifiersIdentifier(conf.HyperchainNodeOus.ClientOuIdentifier.Certificate)
				if err != nil {
					return err
				}
				msp.clientOU.CertifiersIdentifier = certifiersIdentifier
			}
			counter++
		} else {
			msp.clientOU = nil
		}

		// peer organizational unit
		if conf.HyperchainNodeOus.PeerOuIdentifier != nil {
			msp.peerOU = &OUIdentifier{OrganizationalUnitIdentifier: conf.HyperchainNodeOus.PeerOuIdentifier.OrganizationalUnitIdentifier}
			if len(conf.HyperchainNodeOus.PeerOuIdentifier.Certificate) != 0 {
				certifiersIdentifier, err := msp.getCertifiersIdentifier(conf.HyperchainNodeOus.PeerOuIdentifier.Certificate)
				if err != nil {
					return err
				}
				msp.peerOU.CertifiersIdentifier = certifiersIdentifier
			}
			counter++
		} else {
			msp.peerOU = nil
		}

		// admin organizational unit
		if conf.HyperchainNodeOus.AdminOuIdentifier != nil {
			msp.adminOU = &OUIdentifier{OrganizationalUnitIdentifier: conf.HyperchainNodeOus.AdminOuIdentifier.OrganizationalUnitIdentifier}
			if len(conf.HyperchainNodeOus.AdminOuIdentifier.Certificate) != 0 {
				certifiersIdentifier, err := msp.getCertifiersIdentifier(conf.HyperchainNodeOus.AdminOuIdentifier.Certificate)
				if err != nil {
					return err
				}
				msp.adminOU.CertifiersIdentifier = certifiersIdentifier
			}
			counter++
		} else {
			msp.adminOU = nil
		}

		// orderer organizational unit
		if conf.HyperchainNodeOus.OrdererOuIdentifier != nil {
			msp.ordererOU = &OUIdentifier{OrganizationalUnitIdentifier: conf.HyperchainNodeOus.OrdererOuIdentifier.OrganizationalUnitIdentifier}
			if len(conf.HyperchainNodeOus.OrdererOuIdentifier.Certificate) != 0 {
				certifiersIdentifier, err := msp.getCertifiersIdentifier(conf.HyperchainNodeOus.OrdererOuIdentifier.Certificate)
				if err != nil {
					return err
				}
				msp.ordererOU.CertifiersIdentifier = certifiersIdentifier
			}
			counter++
		} else {
			msp.ordererOU = nil
		}

		if counter == 0 {
			msp.ouEnforcement = false
		}
	}

	return nil
}

func (msp *bccspmsp) setupSigningIdentity(conf *pbmsp.HyperchainMSPConfig) error {
	if conf.SigningIdentity != nil {
		signingId, err := msp.getSigningIdentityFromConf(conf.SigningIdentity)
		if err != nil {
			return err
		}

		expirationTime := signingId.ExpiresAt()
		now := time.Now()
		if expirationTime.After(now) {
			mspLogger.Debugf("Signing identity expires at [%s].", expirationTime.Format(time.RFC3339))
		} else if expirationTime.IsZero() {
			mspLogger.Warn("Signing identity has unknown expiration time.")
		} else {
			return fmt.Errorf("signning identity has expired [%fs] ago", expirationTime.Sub(now).Seconds())
		}

		msp.signer = signingId
	}

	return nil
}

func (msp *bccspmsp) setupOUs(conf *pbmsp.HyperchainMSPConfig) error {
	msp.ouIdentifiers = make(map[string][][]byte)

	for _, ou := range conf.OrganizationalUnitIdentifiers {
		certifiersIdentifier, err := msp.getCertifiersIdentifier(ou.Certificate)
		if err != nil {
			return err
		}

		found := false

		for _, id := range msp.ouIdentifiers[ou.OrganizationalUnitIdentifier] {
			// 这种情况一般来说不会出现的吧
			if bytes.Equal(id, certifiersIdentifier) {
				mspLogger.Warnf("Duplicate found in organizational unit identifiers [%s] [%v]", ou.OrganizationalUnitIdentifier, id)
				found = true
				break
			}
		}

		if !found {
			msp.ouIdentifiers[ou.OrganizationalUnitIdentifier] = append(msp.ouIdentifiers[ou.OrganizationalUnitIdentifier], certifiersIdentifier)
		}
	}

	return nil
}

func (msp *bccspmsp) setupTLSCAs(conf *pbmsp.HyperchainMSPConfig) error {
	opts := &x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}

	// 1. 从配置信息中获取 tls ca 证书。
	allCerts := make([]*x509.Certificate, 0)
	msp.tlsRootCerts = make([][]byte, len(conf.TlsRootCerts))
	for i, trustedCert := range conf.TlsRootCerts {
		cert, err := getCertFromPEM(trustedCert)
		if err != nil {
			return err
		}

		msp.tlsRootCerts[i] = trustedCert
		opts.Roots.AddCert(cert)
		allCerts = append(allCerts, cert)
	}

	msp.tlsIntermediateCerts = make([][]byte, len(conf.TlsIntermediateCerts))
	for i, trustedCert := range conf.TlsIntermediateCerts {
		cert, err := getCertFromPEM(trustedCert)
		if err != nil {
			return err
		}

		msp.tlsIntermediateCerts[i] = trustedCert
		opts.Intermediates.AddCert(cert)
		allCerts = append(allCerts, cert)
	}

	// 2. 验证每个 tls ca 证书的合法性
	for _, cert := range allCerts {
		if _, err := getSKIFromCert(cert); err != nil {
			return fmt.Errorf("ca certificate [sn:%s] has problem to get subject key identifier: [%s]", cert.SerialNumber.String(), err.Error())
		}

		opts.CurrentTime = cert.NotBefore.Add(time.Second) // 设定为证书起始时间之后的一秒
		if err := msp.validateTLSCAIdentity(cert, opts); err != nil {
			return err
		}
	}

	return nil
}

// setupV1 设置 msp：
//  1. 设置 msp 采用的哈希算法，目前仅支持 SHA256 哈希算法；
//  2. 设置根 ca 和中级 ca 证书列表；
//  3. 为 msp 设置管理员；
//  4. 为 msp 设置证书撤销列表；
//  5. 最终完成 CA 的设置，第 5 步 必须要在第 4 步之后，因为完成 CA 的设置过程中，需要验证 CA 的合法性，这个时候需要检查 CA 是否存在于证书撤销列表中；
//  6. 设置签名身份；
//  7. 设置 tls ca 证书；
//  8. 设置 organizational unit；
//  9. 检查所设置的管理员身份是否被撤销。
func (msp *bccspmsp) setupV1(conf *pbmsp.HyperchainMSPConfig) error {
	if err := msp.preSetupV1(conf); err != nil {
		return err
	}

	if err := msp.postSetupV1(); err != nil {
		return err
	}

	return nil
}

// setupV11 设置 msp：
//  1. 设置 msp 采用的哈希算法，目前仅支持 SHA256 哈希算法；
//  2. 设置根 ca 和中级 ca 证书列表；
//  3. 为 msp 设置管理员；
//  4. 为 msp 设置证书撤销列表；
//  5. 最终完成 CA 的设置，第 5 步 必须要在第 4 步之后，因为完成 CA 的设置过程中，需要验证 CA 的合法性，这个时候需要检查 CA 是否存在于证书撤销列表中；
//  6. 设置签名身份；
//  7. 设置 tls ca 证书；
//  8. 设置 organizational unit；
//  9. 设置节点 organizational unit；
//  10. 检查所设置的管理员身份是否被撤销，检查管理员是否是 client。
func (msp *bccspmsp) setupV11(conf *pbmsp.HyperchainMSPConfig) error {
	if err := msp.preSetupV11(conf); err != nil {
		return err
	}

	if err := msp.postSetupV11(); err != nil {
		return err
	}

	return nil
}

// setupV142 设置 msp：
//  1. 设置 msp 采用的哈希算法，目前仅支持 SHA256 哈希算法；
//  2. 设置根 ca 和中级 ca 证书列表；
//  3. 为 msp 设置管理员；
//  4. 为 msp 设置证书撤销列表；
//  5. 最终完成 CA 的设置，第 5 步 必须要在第 4 步之后，因为完成 CA 的设置过程中，需要验证 CA 的合法性，这个时候需要检查 CA 是否存在于证书撤销列表中；
//  6. 设置签名身份；
//  7. 设置 tls ca 证书；
//  8. 设置 organizational unit；
//  9. 设置节点 organizational unit；
//  10. 检查所设置的管理员身份是否被撤销，检查管理员是否是 client 或 admin。
func (msp *bccspmsp) setupV142(conf *pbmsp.HyperchainMSPConfig) error {
	if err := msp.preSetupV142(conf); err != nil {
		return err
	}

	if err := msp.postSetupV142(); err != nil {
		return err
	}

	return nil
}

// preSetupV1 必须在 postSetupV1 签名执行，因为必须在 preSetupV1 设置好管理员身份后，postSetupV1 才能有机会验证管理员身份是否被撤销。
func (msp *bccspmsp) preSetupV1(conf *pbmsp.HyperchainMSPConfig) error {
	// 1. 设置 msp 采用的哈希算法，目前仅支持 SHA256 哈希算法。
	if err := msp.setupCrypto(conf); err != nil {
		return err
	}

	// 2. 设置根 ca 和中级 ca 证书列表。
	if err := msp.setupCAs(conf); err != nil {
		return err
	}

	// 3. 为 msp 设置管理员。
	if err := msp.setupAdmins(conf); err != nil {
		return err
	}

	// 4. 为 msp 设置证书撤销列表。
	if err := msp.setupRLs(conf); err != nil {
		return err
	}

	// 5. 最终完成 CA 的设置，第 5 步 必须要在第 4 步之后，因为完成 CA 的设置过程中，需要验证 CA 的合法性，
	// 这个时候需要检查 CA 是否存在于证书撤销列表中。
	if err := msp.finalizeSetupCAs(); err != nil {
		return err
	}

	// 6. 设置签名身份。
	if err := msp.setupSigningIdentity(conf); err != nil {
		return err
	}

	// 7. 设置 tls ca 证书。
	if err := msp.setupTLSCAs(conf); err != nil {
		return err
	}

	// 8. 设置 organizational unit。
	if err := msp.setupOUs(conf); err != nil {
		return err
	}

	return nil
}

func (msp *bccspmsp) preSetupV11(conf *pbmsp.HyperchainMSPConfig) error {
	if err := msp.preSetupV1(conf); err != nil {
		return err
	}

	if err := msp.setupNodeOUs(conf); err != nil {
		return err
	}

	return nil
}

// preSetupV142 相比于 preSetupV1 来说，多了一步设置节点 organizational unit 的步骤。
func (msp *bccspmsp) preSetupV142(conf *pbmsp.HyperchainMSPConfig) error {
	if err := msp.preSetupV1(conf); err != nil {
		return err
	}

	if err := msp.setupNodeOUsV142(conf); err != nil {
		return err
	}

	return nil
}

// postSetupV1 逐一检查在本 msp 处注册的管理员身份是否被撤销。
func (msp *bccspmsp) postSetupV1() error {
	for _, admin := range msp.admins {
		if err := admin.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (msp *bccspmsp) postSetupV11() error {
	if !msp.ouEnforcement {
		// 检查管理员身份是否被撤销
		return msp.postSetupV1()
	}

	// 检查管理员是否是 client
	principalRaw, err := proto.Marshal(&pbmsp.MSPRole{Role: pbmsp.MSPRole_CLIENT, MspIdentifier: msp.name})
	if err != nil {
		return err
	}

	principal := &pbmsp.MSPPrincipal{
		PrincipalClassification: pbmsp.MSPPrincipal_ROLE,
		Principal:               principalRaw,
	}

	for _, admin := range msp.admins {
		if err = admin.SatisfiesPrincipal(principal); err != nil {
			return fmt.Errorf("admin [%s] is invalid", admin.GetIdentifier().Id)
		}
	}

	return nil
}

// postSetupV142 检查管理员是否是 client 或者 admin，如果都不是，则会报错。
func (msp *bccspmsp) postSetupV142() error {
	if !msp.ouEnforcement {
		// 检查在本 msp 处注册的管理员身份是否被撤销
		return msp.postSetupV1()
	}

	for _, admin := range msp.admins {
		err1 := msp.hasOURole(admin, pbmsp.MSPRole_CLIENT)
		err2 := msp.hasOURole(admin, pbmsp.MSPRole_ADMIN)
		if err1 != nil && err2 != nil {
			return fmt.Errorf("admin [%s] is invalid", admin.GetIdentifier().Id)
		}
	}

	return nil
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

// isIdentitySignedInCanonicalForm 一般情况下，该方法都只会返回 nil。
func isIdentitySignedInCanonicalForm(sig []byte, mspID string, identityPEM []byte) error {
	r, s, err := bccsp.UnmarshalECDSASignature(sig)
	if err != nil {
		return err
	}

	expectedSig, err := bccsp.MarshalECDSASignature(r, s)
	if err != nil {
		return err
	}

	if !bytes.Equal(expectedSig, sig) {
		return fmt.Errorf("identity [%s] for MSP [%s] has a non canonical signature", identityPEM, mspID)
	}

	return nil
}

// verifyLegacyNameConstraints 给定一个证书链，这个证书链中的第一个证书是端证书，最后一个证书是根证书。
//  1. 所以如果给定的证书链中只有一个证书，那么该证书为 CA 证书，不必检查，直接返回 nil，否则进入第 2 步；
//  2. 检查端证书的扩展字段里是否支持 SAN，如果支持的话，则不必继续检查，返回 nil，否则进入第 3 步；
//  3. 检查端证书后面的中级证书和根证书的扩展字段，如果支持命名约束（NameConstraints），则返回错误，因为第 2 步的检查结果显示端证书的扩展字段不支持 SAN。
func verifyLegacyNameConstraints(chain []*x509.Certificate) error {
	if len(chain) < 2 {
		// 是根证书，不必检查
		return nil
	}

	// 检查证书链中第一个证书是否支持多个不同域名的解析。
	if oidInExtensions(oidExtensionSubjectAltName, chain[0].Extensions) {
		return nil
	}

	if !validHostname(chain[0].Subject.CommonName) {
		return nil
	}

	for _, c := range chain[1:] {
		// 检查后面一溜的的中级 CA 证书，和最后的根 CA 证书，扩展里规定了 NameConstraints 的，就必须也规定了 SubjectAltName。
		if oidInExtensions(oidExtensionNameConstraints, c.Extensions) {
			return x509.CertificateInvalidError{Cert: chain[0], Reason: x509.NameConstraintsWithoutSANs}
		}
	}

	return nil
}

// oidInExtensions ObjectIdentifier 类型用于表示 ASN.1 OBJECT IDENTIFIER 类型。
func oidInExtensions(oid asn1.ObjectIdentifier, exts []pkix.Extension) bool {
	for _, ext := range exts {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// validHostname hostname 不合法的话会返回 false。
func validHostname(host string) bool {
	// 去掉 host 尾部的点号
	host = strings.TrimSuffix(host, ".")

	if len(host) == 0 {
		return false
	}

	for i, part := range strings.Split(host, ".") {
		if part == "" {
			return false
		}
		if i == 0 && part == "*" {
			continue
		}
		for j, c := range part {
			if 'a' <= c && c <= 'z' {
				continue
			}
			if '0' <= c && c <= '9' {
				continue
			}
			if 'A' <= c && c <= 'Z' {
				continue
			}
			if c == '-' && j != 0 {
				continue
			}
			if c == '_' || c == ':' {
				continue
			}
			return false
		}
	}

	return true
}

func collectPrincipals(principal *pbmsp.MSPPrincipal, version MSPVersion) ([]*pbmsp.MSPPrincipal, error) {
	switch principal.PrincipalClassification {
	case pbmsp.MSPPrincipal_COMBINED:
		if version <= MSPv1_1 {
			return nil, fmt.Errorf("invalid principal type [%d]", principal.PrincipalClassification)
		}

		principals := &pbmsp.CombinedPrincipal{}
		if err := proto.Unmarshal(principal.Principal, principals); err != nil {
			return nil, fmt.Errorf("failed unmarshaling CombinedPrincipal from principal: [%s]", err.Error())
		}
		if len(principals.Principals) == 0 {
			return nil, errors.New("no principals in CombinedPrincipal")
		}
		// 到目前为止都还是读取 Principal，没说怎么使用
		var ps []*pbmsp.MSPPrincipal
		for _, p := range principals.Principals {
			if s, err := collectPrincipals(p, version); err == nil {
				ps = append(ps, s...)
			} else {
				return nil, err
			}
		}

		return ps, nil
	default:
		return []*pbmsp.MSPPrincipal{principal}, nil
	}
}

// getSKIFromCert 获取 x509 证书的 Subject Key Identifier。
func getSKIFromCert(cert *x509.Certificate) ([]byte, error) {
	var ski []byte

	for _, ext := range cert.Extensions {
		if reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 14}) { // subject key identifier
			if _, err := asn1.Unmarshal(ext.Value, &ski); err != nil {
				return nil, err
			}
			return ski, nil
		}
	}

	return nil, errors.New("asn1.ObjectIdentifier{2, 5, 29, 14} is not found in certificate's extensions")
}

// getAKIFromCert 获取 x509 证书的 Authority kEY Identifier。
func getAKIFromCert(crl *x509.RevocationList) ([]byte, error) {
	type authorityKeyIdentifier struct {
		KeyIdentifier             []byte  `asn1:"optional,tag:0"`
		AuthorityCertIssuer       []byte  `asn1:"optional,tag:1"`
		AuthorityCertSerialNumber big.Int `asn1:"optional,tag:2"`
	}

	aki := &authorityKeyIdentifier{}

	for _, ext := range crl.Extensions {
		if reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 35}) {
			if _, err := asn1.Unmarshal(ext.Value, aki); err != nil {
				return nil, err
			}
			return aki.KeyIdentifier, nil
		}
	}

	return nil, errors.New("asn1.ObjectIdentifier{2, 5, 29, 35} is not found in certificate's extensions")
}

func getCertFromPEM(certPEM []byte) (*x509.Certificate, error) {
	if certPEM == nil {
		return nil, vars.ErrorDecodePEMFormatCertificate{MaterialIsNil: true}
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, vars.ErrorDecodePEMFormatCertificate{BlockIsNil: true}
	}

	return x509.ParseCertificate(block.Bytes)
}
