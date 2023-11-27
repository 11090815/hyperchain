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
	internalSetupAdminFunc setupAdminInternalFuncType

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

	// CRL 若干个证书撤销列表，每个撤销列表里存放的撤销的证书都由同一个 Issuer (CA) 发布。
	CRL []*x509.RevocationList

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
//  1. 如果给定的 principal.PrincipalClassification 等于 pbmsp.MSPPrincipal_ROLE：将 principal.Principal 反序列化成 &pbmsp.MSPRole{} 后，按照以下顺序验证：
//
//		1.1 如果 mspRole.Role = pbmsp.MSPRole_MEMBER，则验证给定的 Identity 是否被正确签发、是否被撤销、Identity 的组织是否正确；
//
//		1.2 如果 mspRole.Role = pbmsp.MSPRole_ADMIN，则判断给定的 Identity 是否在 msp 的管理员列表中；
//
//		1.3 如果 mspRole.Role = pbmsp.MSPRole_CLIENT，则按照 mspRole.Role = pbmsp.MSPRole_PEER 时的情况验证给定的 Identity；
//
//		1.4 如果 mspRole.Role = pbmsp.MSPRole_PEER，则验证给定的 Identity 是否被正确签发、是否被撤销、Identity 的组织是否正确，并检查给定的 Identity 是否属于与指定 MSPRole 关联的组织单位。
//
//		1.5 如果 mspRole.Role = 其他值，则报错。
//
//	2. 如果给定的 principal.PrincipalClassification 等于 pbmsp.MSPPrincipal_IDENTITY：利用 msp.DeserializeIdentity() 方法解析 principal.Principal 得到 Identity 实例 principalID：
//
//		2.1 验证解析得到的 principalID.(*identity).cert.Raw 和给定的 id.(*identity).cert.Raw 一不一样。
//
//	3. 如果给定的 principal.PrincipalClassification 等于 pbmsp.MSPPrincipal_ORGANIZATION_UNIT，将 principal.Principal 反序列化成一个 *pbmsp.OrganizationUnit 实例 ou 后，按照以下顺序进行验证：
//
//		3.1 判断 ou.MspIdentifier 与 msp.name 一不一样；
//
//		3.2 验证给定的 Identity 是否被正确签发、是否被撤销、Identity 的组织是否正确；
//
//		3.3 验证与给定 Identity 管理的组织是否与 ou 里的组织单元匹配，如果存在一个匹配，则验证通过。
//
//	4. 如果给定的 principal.PrincipalClassification 等于其他值，则直接报错。
func (msp *bccspmsp) satisfiesPrincipalInternalPreV13(id Identity, principal *pbmsp.MSPPrincipal) error {
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

// isInAdmin 判断给定的身份是否在 msp 的管理员列表中。
func (msp *bccspmsp) isInAdmin(id *identity) bool {
	for _, adminIdentity := range msp.admins {
		if bytes.Equal(id.cert.Raw, adminIdentity.(*identity).cert.Raw) {
			return true
		}
	}
	return false
}

// getIdentityFromConf 给定某个身份的 x509 证书的 PEM 编码的数据，然后从该证书中提取出以下信息：
//  1. x509.Certificate
//  2. bccsp.Key
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

// getCertificateChainIdentifierFromChain 给定一个证书链，计算该证书链的哈希值。
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

func (msp *bccspmsp) validateCertAgainstChain(cert *x509.Certificate, validationChain []*x509.Certificate) error {
	// 1. 获取签署待验证证书的 CA 的 SKI 标识符。
	ski, err := getSKIFromCert(validationChain[1])
	if err != nil {
		return fmt.Errorf("cannot obtain subject key identifier from the certificate of the signer")
	}

	for _, crl := range msp.CRL {
		aki, err := getAKIFromCert(crl)
		if err != nil {
			return fmt.Errorf("could not obtain authority identifier from the certificate revocation list: [%s]", err.Error())
		}

		if bytes.Equal(aki, ski) {
			// 证书撤销列表 AKI 与 CA 证书的 SKI 一致，说明此撤销列表里的证书可能由该 CA 证书发布。
			for _, rc := range crl.RevokedCertificates {
				if rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					// 如果撤销列表里的某个证书的序列号与待验证的证书序列号一样，那么待验证的证书已经被加入到撤销列表中了，
					// 继续检查该撤销了表是否由 CA 发布的，如果是的话，则可以确定该证书已经被撤销了。
					if err = crl.CheckSignatureFrom(validationChain[1]); err != nil {
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
		return errors.New("NodeOUs is not activated, cannot tell apart identities.")
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
