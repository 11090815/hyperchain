package crypto

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// tbsCertificate 证书的基本信息
type tbsCertificate struct {
	Raw          asn1.RawContent
	Version      int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber *big.Int
	// CA 用于签署证书的算法标识符
	SignatureAlgorithm pkix.AlgorithmIdentifier
	// 签署和颁发该证书的发行人标识符
	Issuer asn1.RawValue
	// 证书的有效期
	Validity validity
	// 数字证书中存放的信息主题
	Subject         asn1.RawValue
	PublicKey       publicKeyInfo
	UniqueId        asn1.BitString   `asn1:"optional",tag:1`
	SubjectUniqueId asn1.BitString   `asn1:"optional",tag:2`
	Extensions      []pkix.Extension `asn1:"optional,explicit",tag:3`
}

type certificate struct {
	Raw asn1.RawContent
	// 证书的基本信息
	TBSCertificate tbsCertificate
	// CA 签名数字证书的算法标识符
	SignatureAlgorithm pkix.AlgorithmIdentifier
	// 根据 TBSCertificate 通过 ASN1.DER 编码后的数据用 SignatureAlogrithm 算法签名得出的数字签名
	SignatureValue asn1.BitString
}

// func SanitizeX509Cert(initialPEM []byte) ([]byte, error) {
// 	der, _ := pem.Decode(initialPEM)
// 	if der == nil {
// 		return nil, fmt.Errorf("failed decoding identity bytes: [%s]", initialPEM)
// 	}
// 	certificate, err := x509.ParseCertificate(der.Bytes)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed parsing asn1.der format certificate: [%s]", err.Error())
// 	}

// }
