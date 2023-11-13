package tlsgen

import (
	"crypto"
)

type CA struct {
	*CertKeyPair
}

// NewCA 生成一个 CA，该 CA 包含 ECDSA 体制下的公钥、私钥、签名者（背书者）、证书。CA 的证书是由自己签发的：
//   - 私钥（Key）：在生成 CA 时，通过 ecdsa.GenerateKey 方法随机生成私钥，然后将该私钥转换为 PKCS#8 ASN.1 DER PEM 格式，作为 Key 的值；
//   - 公钥（Cert）：利用前面生成的私钥对其自己的公钥进行签名（self-sign），生成 PKCS#8 ASN.1 DER 格式的证书，然后再将其转换为 PEM 格式，作为 Cert 的值；
//   - 证书（TLSCert）：利用前面生成的私钥对其自己的公钥进行签名（self-sign），生成 PKCS#8 ASN.1 DER 格式的证书，然后对其进行解析，得到 *x509.Certificate，并赋值给 TLSCert；
//   - 背书者（Signer）：其实就是前面利用 ecdsa.GenerateKey 方法随机生成的私钥。
func NewCA() (*CA, error) {
	// 没有父级证书，没有背书节点，自己给自己签署。
	certKeyPair, err := newCertKeyPair(true, false, nil, nil)
	if err != nil {
		return nil, err
	}
	return &CA{CertKeyPair: certKeyPair}, nil
}

// NewIntermediateCA 利用自己的私钥作为中级 CA（下级 CA）的背书者，然后利用自己的证书作为中级 CA 的父级证书，生成一个中级 CA。
// 中级 CA 的私钥是随机生成的。
//   - 私钥（Key）：在生成 CA 时，通过 ecdsa.GenerateKey 方法随机生成私钥，然后将该私钥转换为 PKCS#8 ASN.1 DER PEM 格式，作为 Key 的值；
//   - 公钥（Cert）：利用父级 CA 的私钥对自己的公钥进行签名，生成 PKCS#8 ASN.1 DER 格式的证书，然后再将其转换为 PEM 格式，作为 Cert 的值；
//   - 证书（TLSCert）：利用父级 CA 的私钥对自己的公钥进行签名，生成 PKCS#8 ASN.1 DER 格式的证书，然后对其进行解析，得到 *x509.Certificate，并赋值给 TLSCert；
//   - 背书者（Signer）：父级 CA 的私钥。
func (ca *CA) NewIntermediateCA() (*CA, error) {
	certKeyPair, err := newCertKeyPair(true, false, ca.endorser, ca.tlsCert) // 中级 CA 也是 CA，所以 isCA 变量是 true
	if err != nil {
		return nil, err
	}
	return &CA{CertKeyPair: certKeyPair}, nil
}

// NewClientCertKeyPair 利用自己的证书作为客户端证书的父级证书，然后利用自己的私钥为客户端签署证书（客户端的公钥），客户端的私钥是随机生成的。
// 一般来说，只有同一个 CA 创建的客户端和服务端，相互之间才能建立 TLS 连接。
func (ca *CA) NewClientCertKeyPair() (*CertKeyPair, error) {
	return newCertKeyPair(false, false, ca.endorser, ca.tlsCert)
}

// NewServerCertKeyPair 利用自己的证书作为服务端证书的父级证书，然后利用自己的私钥为服务端签署证书（服务端的公钥），服务端的私钥是随机生成的。
func (ca *CA) NewServerCertKeyPair(hosts ...string) (*CertKeyPair, error) {
	return newCertKeyPair(false, true, ca.endorser, ca.tlsCert, hosts...)
}

// CertBytes 返回 x509.Certficate 的 PKCS#8 ASN.1 DER PEM 格式的数据。
//
// Deprecated: 该方法被 PublicKeyPEM 方法替代。
func (ca *CA) CertBytes() []byte {
	return ca.cert
}

// Endorser 返回该 CA 的签名背书者。
func (ca *CA) Endorser() crypto.Signer {
	return ca.endorser
}
