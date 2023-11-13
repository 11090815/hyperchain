package msp

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// func x509CertToPEM(cert *x509.Certificate) string {

// }

// isECDSASignedCert 是否是由 ECDSA 签名算法签署的 x509 证书。
func isECDSASignedCert(cert *x509.Certificate) bool {
	return cert.SignatureAlgorithm == x509.ECDSAWithSHA1 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA256 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA384 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA512
}
