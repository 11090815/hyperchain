package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"time"
)

func newTemplate(now time.Time) x509.Certificate {
	sn, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	template := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:   "github.com",
			Organization: []string{"GitHub"},
			Country:      []string{"CN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  asn1.ObjectIdentifier{2, 5, 4, 42},
					Value: "Gopher",
				},
				{
					Type:  asn1.ObjectIdentifier{2, 5, 4, 6},
					Value: "Blockchain",
				},
			},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(time.Hour * 24 * 365 * 10),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		SubjectKeyId:          []byte{1, 2, 3, 4},
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{{1, 2, 3}, {2, 59, 1}},
		BasicConstraintsValid: true,
		IsCA:                  true,
		OCSPServer:            []string{"https://onlinecertificatestatusprotocol.nwpu.com"},
		IssuingCertificateURL: []string{"https://issuingcertificateurl.nwpu.com"},
		DNSNames:              []string{"https://dns.nwpu.com"},
		EmailAddresses:        []string{"1378406814@mail.nwpu.edu.cn"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("2001:4860:0:2001::68")},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{{1, 2, 3}},
		PermittedDNSDomains:   []string{"nwpu.com", ".nwpu.com"},
		CRLDistributionPoints: []string{"https://crl1.nwpu.com/ca1.crl", "https://crl2.nwpu.com/ca1.crl"},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 2, 3, 4},
				Value: []byte("extra extension"),
			},
		},
	}

	return template
}

func generateCACert() (*x509.Certificate, crypto.Signer, error) {
	template := newTemplate(time.Now())
	template.KeyUsage = template.KeyUsage | x509.KeyUsageCRLSign
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed generating ca certificate: [%s]", err.Error())
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed generating ca certificate: [%s]", err.Error())
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed generating ca certificate: [%s]", err.Error())
	}

	f, err := os.OpenFile("cacerts/cacert.pem", os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
	if err != nil {
		return nil, nil, fmt.Errorf("failed generating ca certificate: [%s]", err.Error())
	}

	if err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: raw}); err != nil {
		return nil, nil, fmt.Errorf("failed generating ca certificate: [%s]", err.Error())
	}
	f.Close()

	return cert, privateKey, nil
}

func generateAdminCert(cacert *x509.Certificate, signer crypto.Signer) error {
	template := newTemplate(time.Now())
	template.IsCA = false

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed generating admin certificate: [%s]", err.Error())
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, cacert, &privateKey.PublicKey, signer)
	if err != nil {
		return fmt.Errorf("failed generating admin certificate: [%s]", err.Error())
	}

	f, err := os.OpenFile("admincerts/admincert.pem", os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
	if err != nil {
		return fmt.Errorf("failed generating admin certificate: [%s]", err.Error())
	}
	if err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: raw}); err != nil {
		return fmt.Errorf("failed generating admin certificate: [%s]", err.Error())
	}
	f.Close()

	fmt.Println("admin证书的sn:", template.SerialNumber.String())

	return nil
}

func generateRevokedSignCerts(cacert *x509.Certificate, signer crypto.Signer) error {
	template := newTemplate(time.Now())
	template.IsCA = false
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed generating signing certificate: [%s]", err.Error())
	}

	hash := sha256.New()
	bz := elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y)
	hash.Write(bz)
	digest := hash.Sum(nil)
	alia := hex.EncodeToString(digest)
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed generating signing certificate: [%s]", err.Error())
	}
	f, err := os.OpenFile(fmt.Sprintf("keystore/%s_private_key", alia), os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
	if err != nil {
		return fmt.Errorf("failed generating signing certificate: [%s]", err.Error())
	}
	if err = pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return fmt.Errorf("failed generating signing certificate: [%s]", err.Error())
	}
	f.Close()

	raw, err := x509.CreateCertificate(rand.Reader, &template, cacert, &privateKey.PublicKey, signer)
	if err != nil {
		return fmt.Errorf("failed generating admin certificate: [%s]", err.Error())
	}
	f, err = os.OpenFile("signcerts/signcert-revoked.pem", os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
	if err != nil {
		return fmt.Errorf("failed generating signing certificate: [%s]", err.Error())
	}
	if err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: raw}); err != nil {
		return fmt.Errorf("failed generating signing certificate: [%s]", err.Error())
	}
	f.Close()

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return fmt.Errorf("failed generating signing certificate: [%s]", err.Error())
	}

	num, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	tmpl := x509.RevocationList{
		Number:              num,
		RevokedCertificates: []pkix.RevokedCertificate{pkix.RevokedCertificate{SerialNumber: cert.SerialNumber, RevocationTime: time.Now().Add(time.Minute * 20)}},
	}
	rawRl, err := x509.CreateRevocationList(rand.Reader, &tmpl, cacert, signer)
	if err != nil {
		return fmt.Errorf("failed generating revocation list: [%s]", err.Error())
	}

	f, err = os.OpenFile("crls/crl.pem", os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
	if err != nil {
		return fmt.Errorf("failed generating revocation list: [%s]", err.Error())
	}
	if err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: rawRl}); err != nil {
		return fmt.Errorf("failed generating revocation list: [%s]", err.Error())
	}
	f.Close()

	fmt.Println("被撤销证书的sn:", cert.SerialNumber.String())

	return nil
}

func main() {
	cacert, signer, err := generateCACert()
	if err != nil {
		log.Fatal(err)
	}
	if err = generateAdminCert(cacert, signer); err != nil {
		log.Fatal(err)
	}
	if err = generateRevokedSignCerts(cacert, signer); err != nil {
		log.Fatal(err)
	}
}
