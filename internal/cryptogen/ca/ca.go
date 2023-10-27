package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/11090815/hyperchain/internal/cryptogen/csp"
)

type CA struct {
	Name               string // 存储该证书的文件名：[name]-cert.pem
	Country            string
	Province           string
	Locality           string
	OrganizationalUnit string
	StreetAddress      string
	PostalCode         string
	Signer             crypto.Signer // SignCert 与 Signer 是一对公私钥
	SignCert           *x509.Certificate
}

// SignCertificate 给定一个公钥，利用 CA 的私钥对其进行签名，签署得到一个 x509 证书。
func (ca *CA) SignCertificate(baseDir, name string, orgUnits, alternateNames []string, publicKey *ecdsa.PublicKey, ku x509.KeyUsage, eku []x509.ExtKeyUsage) (*x509.Certificate, error) {
	template := x509Template()
	template.KeyUsage = ku
	template.ExtKeyUsage = eku

	subject := subjectTemplateAdditional(ca.Country, ca.Province, ca.Locality, ca.OrganizationalUnit, ca.StreetAddress, ca.PostalCode)
	subject.CommonName = name
	subject.OrganizationalUnit = append(subject.OrganizationalUnit, orgUnits...)

	template.Subject = subject

	for _, san := range alternateNames {
		ip := net.ParseIP(san)
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	return genECDSACertificate(baseDir, name, &template, ca.SignCert, publicKey, ca.Signer)
}

/*** 🐋 ***/

// 生成证书的组件

// NewCA 传递的第三个参数 name 用来定义存储证书的文件名。
func NewCA(baseDir, org, name, country, province, locality, orgUnit, streetAddress, postalCode string) (*CA, error) {
	// 创建目录，用来存储密钥
	err := os.MkdirAll(baseDir, os.FileMode(0755))
	if err != nil {
		return nil, err
	}

	// 创建密钥，并将其存储到指定的目录中
	privateKey, err := csp.GeneratePrivateKey(baseDir)
	if err != nil {
		return nil, err
	}

	template := x509Template()
	template.IsCA = true
	template.KeyUsage = template.KeyUsage | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

	subject := subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode)
	subject.Organization = append(subject.Organization, org)
	subject.CommonName = name

	template.Subject = subject

	raw := elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	template.SubjectKeyId = hash.Sum(nil)

	cert, err := genECDSACertificate(baseDir, name, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return &CA{
		Name:               name,
		Signer:             &csp.ECDSASigner{PrivateKey: privateKey},
		SignCert:           cert,
		Country:            country,
		Province:           province,
		Locality:           locality,
		OrganizationalUnit: orgUnit,
		StreetAddress:      streetAddress,
		PostalCode:         postalCode,
	}, nil
}

// genECDSACertificate 提供的参数 signer 实际上是一个私钥，它必须与提供的参数 parent 里的公钥对应。
func genECDSACertificate(baseDir, name string, template, parent *x509.Certificate, publicKey *ecdsa.PublicKey, signer interface{}) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		return nil, err
	}

	// 如果目录不存在，则 os.Create 会自己创建一个目录
	certFile, err := os.Create(filepath.Join(baseDir, name+"-cert.pem"))
	if err != nil {
		return nil, err
	}

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

func x509Template() x509.Certificate {
	serialNum, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber:          serialNum,
		NotBefore:             time.Now().Add(time.Minute * (-5)),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 10),
		BasicConstraintsValid: true,
	}

	return template
}

func subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode string) pkix.Name {
	name := subjectTemplate()

	if country != "" {
		name.Country = []string{country}
	}

	if province != "" {
		name.Province = []string{province}
	}

	if locality != "" {
		name.Locality = []string{locality}
	}

	if orgUnit != "" {
		name.OrganizationalUnit = []string{orgUnit}
	}

	if streetAddress != "" {
		name.StreetAddress = []string{streetAddress}
	}

	if postalCode != "" {
		name.PostalCode = []string{postalCode}
	}

	return name
}

func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"CN"},
		Province: []string{"Anhui"},
		Locality: []string{"Hefei"},
	}
}

/*** 🐋 ***/

// 从设备中加载已有证书的组件

func LoadECDSACertificate(path string) (cert *x509.Certificate, err error) {
	walkFunc := func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".pem") {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			block, _ := pem.Decode(raw)
			if block == nil || block.Type != "CERTIFICATE" {
				return fmt.Errorf("wrong certificate pem data: [%s]", path)
			}
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("cannot parse certificate at [%s]", path)
			}
		}
		return nil
	}

	return cert, filepath.Walk(path, walkFunc)
}