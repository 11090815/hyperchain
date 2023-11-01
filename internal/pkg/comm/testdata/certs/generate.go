package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"CN"},
		Province: []string{"Anhui"},
		Locality: []string{"Hefei"},
	}
}

func x509Template() (x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		return x509.Certificate{}, err
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             now,
		NotAfter:              now.Add(24 * 365 * 10 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	return template, nil
}

func genECDSAKey(name string) (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	keyFile, err := os.Create(fmt.Sprintf("%s-key.pem", name))
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	if err = pem.Encode(keyFile, &pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return nil, err
	}

	return privateKey, nil
}

func genECDSACertificate(name string, template, parent *x509.Certificate, pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey) (*x509.Certificate, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	certFile, err := os.Create(fmt.Sprintf("%s-cert.pem", name))
	if err != nil {
		return nil, err
	}
	defer certFile.Close()

	if err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, err
	}

	return cert, nil
}

func genECDSAServerCertificate(name string, signKey *ecdsa.PrivateKey, signCert *x509.Certificate) error {
	key, err := genECDSAKey(name)
	if err != nil {
		return err
	}

	template, err := x509Template()
	if err != nil {
		return err
	}

	subject := subjectTemplate()
	subject.Organization = []string{name}
	subject.CommonName = "localhost"
	template.Subject = subject

	if _, err = genECDSACertificate(name, &template, signCert, &key.PublicKey, signKey); err != nil {
		return err
	}

	return nil
}

func genECDSAClientCertificate(name string, signKey *ecdsa.PrivateKey, signCert *x509.Certificate) error {
	key, err := genECDSAKey(name)
	if err != nil {
		return err
	}

	template, err := x509Template()
	if err != nil {
		return err
	}

	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	subject := subjectTemplate()
	subject.Organization = []string{name}
	subject.CommonName = name
	template.Subject = subject

	if _, err = genECDSACertificate(name, &template, signCert, &key.PublicKey, signKey); err != nil {
		return err
	}

	return nil
}

func genECDSAAuthorityCertificate(name string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := genECDSAKey(name)
	if err != nil {
		return nil, nil, err
	}

	template, err := x509Template()
	if err != nil {
		return nil, nil, err
	}

	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}

	subject := subjectTemplate()
	subject.Organization = []string{name}
	subject.CommonName = name

	template.Subject = subject
	template.SubjectKeyId = []byte{1, 2, 3, 4}

	cert, err := genECDSACertificate(name, &template, &template, &key.PublicKey, key) // 自己给自己签署
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func genECDSAIntermediateAuthorityCertificate(name string, signKey *ecdsa.PrivateKey, signCert *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := genECDSAKey(name)
	if err != nil {
		return nil, nil, err
	}

	template, err := x509Template()
	if err != nil {
		return nil, nil, err
	}

	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}

	subject := subjectTemplate()
	subject.Organization = []string{name}
	subject.CommonName = name

	template.Subject = subject
	template.SubjectKeyId = []byte{1, 2, 3, 4}

	cert, err := genECDSACertificate(name, &template, signCert, &key.PublicKey, signKey)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

func main() {
	numOrgs := 2
	numServers := 2
	numClients := 2
	numChildren := 2
	baseOrgName := "nwpu"
	for i := 1; i < numOrgs; i++ {
		// 生成组织的 CA 证书
		signKey, signCert, err := genECDSAAuthorityCertificate(fmt.Sprintf("%s-%d", baseOrgName, i))
		if err != nil {
			fmt.Printf("Failed generating CA [%s-%d-cert.pem]: [%s]\n", baseOrgName, i, err.Error())
		}

		// 生成组织下面的服务端的证书，非 CA 证书
		for j := 1; j <= numServers; j++ {
			if err := genECDSAServerCertificate(fmt.Sprintf("%s-%d-server-%d", baseOrgName, i, j), signKey, signCert); err != nil {
				fmt.Printf("Failed generating certificate [%s-%d-server-%d-cert.pem]: [%s]\n", baseOrgName, i, j, err.Error())
			}
		}

		// 生成组织下面客户端的证书，非 CA 证书
		for j := 1; j <= numClients; j++ {
			if err := genECDSAClientCertificate(fmt.Sprintf("%s-%d-client-%d", baseOrgName, i, j), signKey, signCert); err != nil {
				fmt.Printf("Failed generating certificate [%s-%d-client-%d-cert.pem]: [%s]\n", baseOrgName, i, j, err.Error())
			}
		}

		for j := 1; j < numChildren; j++ {
			inSignKey, inSignCert, err := genECDSAIntermediateAuthorityCertificate(fmt.Sprintf("%s-%d-intermediate-%d", baseOrgName, i, j), signKey, signCert)
			if err != nil {
				fmt.Printf("Failed generating intermediate CA [%s-%d-intermediate-%d-cert.pem]: [%s]\n", baseOrgName, i, j, err.Error())
			}

			// 生成组织下面的服务端的证书，非 CA 证书
			for k := 1; k <= numServers; k++ {
				if err := genECDSAServerCertificate(fmt.Sprintf("%s-%d-server-%d", baseOrgName, i, k), inSignKey, inSignCert); err != nil {
					fmt.Printf("Failed generating certificate [%s-%d-server-%d-cert.pem]: [%s]\n", baseOrgName, i, k, err.Error())
				}
			}

			// 生成组织下面客户端的证书，非 CA 证书
			for k := 1; k <= numClients; k++ {
				if err := genECDSAClientCertificate(fmt.Sprintf("%s-%d-client-%d", baseOrgName, i, k), inSignKey, inSignCert); err != nil {
					fmt.Printf("Failed generating certificate [%s-%d-client-%d-cert.pem]: [%s]\n", baseOrgName, i, k, err.Error())
				}
			}
		}
	}
}
