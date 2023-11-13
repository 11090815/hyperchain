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
	// SAN(Subject Alternative Name) 是 SSL 标准 x509 中定义的一个扩展。使用了 SAN 字段的 SSL 证书，
	// 可以扩展此证书支持的域名，使得一个证书可以支持多个不同域名的解析。
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

func (msp *bccspmsp) Validate(id Identity) error {
	switch id := id.(type) {
	case *identity:
		return msp.validateIdentity(id)
	default:
		return fmt.Errorf("identity type [%T] not recognized", id)
	}
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

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

func (msp *bccspmsp) getValidityOptsForCert(notBefore time.Time) x509.VerifyOptions {
	var opts x509.VerifyOptions
	opts.Roots = msp.opts.Roots                   // *x509.CertPool
	opts.DNSName = msp.opts.DNSName               // string
	opts.Intermediates = msp.opts.Intermediates   // *x509.CertPool
	opts.KeyUsages = msp.opts.KeyUsages           // []x509.ExtKeyUsage
	opts.CurrentTime = notBefore.Add(time.Second) // time.Time 证书的起始时间

	return opts
}

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
	chain, err := msp.getCertficateChain(id)
	if err != nil {
		return nil, fmt.Errorf("failed getting certificate chain for [%v]: [%s]", id, err.Error())
	}

	return msp.getCertificateChainIdentifierFromChain(chain[1:])
}

func (msp *bccspmsp) getCertficateChain(id Identity) ([]*x509.Certificate, error) {
	switch id := id.(type) {
	case *identity:
		return msp.getCertificateChainForBCCSPIdentity(id)
	default:
		return nil, fmt.Errorf("identity type [%T] not recognized", id)
	}
}

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

func verifyLegacyNameConstraints(chain []*x509.Certificate) error {
	if len(chain) < 2 {
		// 是根证书，不必检查
		return nil
	}

	if oidInExtensions(oidExtensionSubjectAltName, chain[0].Extensions) {
		return nil
	}

	if !validHostname(chain[0].Subject.CommonName) {
		return nil
	}

	for _, c := range chain[1:] {
		// 检查后面一溜的的中级 CA 证书，和最后的根 CA 证书
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
