package msp

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/11090815/hyperchain/internal/cryptogen/ca"
	"github.com/11090815/hyperchain/internal/cryptogen/csp"
	hcmsp "github.com/11090815/hyperchain/msp"
	"gopkg.in/yaml.v3"
)

const (
	CLIENT = iota
	ORDERER
	PEER
	ADMIN
)

const (
	CLIENTOU  = "client"
	PEEROU    = "peer"
	ADMINOU   = "admin"
	ORDEREROU = "orderer"
)

var nodeOUMap = map[int]string{
	CLIENT:  CLIENTOU,
	ORDERER: ORDEREROU,
	PEER:    PEEROU,
	ADMIN:   ADMINOU,
}

/*** 🐋 ***/

// 可导出函数

// GenerateLocalMSP
//  1. 在同一个目录 baseDir (传入的第一个参数) 里创建两个文件夹：msp 和 tls；
//  2. 在 msp 文件夹内创建五个文件夹：cacerts admincerts tlscacerts keystore signcerts；
//  3. 随机生成一个 ECDSA 私钥，并按照 ASN.1 DER PEM 格式对私钥进行编码，将编码后的数据存储到 msp/keystore/private_key 文件中；
//  4. 利用签名 CA 对随机生成的私钥的公钥进行签署，得到一个公钥 x509 证书，然后将证书存储到 msp/signcerts/name-cert.pem 文件中；
//  5. 将签名 CA 的证书和 TLS CA 的证书分别存储到 msp/cacerts 和 msp/tlscacerts 两个目录中；
//  6. 如果需要导出配置文件，则将其导入到 msp/config.yaml 文件中，否则将第 4 步生成的公钥证书存储到 msp/admincerts/name-cert.pem 文件中；
//  7. 为 TLS 随机生成一个 ECDSA 私钥，并将私钥存储到 tls/private_key 文件中 (将私钥编码成 ASN.1 DER PEM 格式后再存储)；
//  8. 利用 TLS CA 对第 7 步生成的私钥的公钥进行签署，得到一个公钥 x509 证书，然后将证书存储到 tls/name-cert.pem 文件中；
//  9. 将 TLS CA 证书的内容写入到 tls/ca.crt 文件中；
//  10. 将 tls/name-cert.pem (第 8 步) 重命名为 tls/client.crt 或者 tls/server.crt；
//  11. 将 tls/private_key (第 7 步) 文件重命名为 tls/client.key 或者 tls/server.key
func GenerateLocalMSP(baseDir, name string, sans []string, signCA *ca.CA, tlsCA *ca.CA, nodeType int, nodeOUs bool) error {
	mspDir := filepath.Join(baseDir, "msp")
	tlsDir := filepath.Join(baseDir, "tls")

	// 创建目录：msp/cacerts msp/admincerts msp/tlscacerts msp/keystore msp/signcerts
	if err := createFolderStructure(mspDir, true); err != nil {
		return err
	}

	if err := os.MkdirAll(tlsDir, os.FileMode(0755)); err != nil {
		return err
	}

	keystore := filepath.Join(mspDir, "keystore")

	privateKey, err := csp.GeneratePrivateKey(keystore)
	if err != nil {
		return err
	}

	cert, err := signCA.SignCertificate(
		filepath.Join(mspDir, "signcerts"), // 为什么在 fabric-samples 对应目录下没有 signcerts 文件夹？
		name,
		[]string{nodeOUMap[nodeType]},
		nil, // alternateNames => nil
		&privateKey.PublicKey,
		x509.KeyUsageDigitalSignature,
		nil,
	)
	if err != nil {
		return err
	}

	if err = x509Export(filepath.Join(mspDir, "cacerts", x509FileName(signCA.Name)), signCA.SignCert); err != nil {
		return err
	}

	if err = x509Export(filepath.Join(mspDir, "tlscacerts", x509FileName(tlsCA.Name)), tlsCA.SignCert); err != nil {
		return err
	}

	if nodeOUs {
		if err = exportConfig(mspDir, filepath.Join("cacerts", x509FileName(signCA.Name)), true); err != nil {
			return err
		}
	} else {
		// 将随机生成的签名私钥的公钥存储到 admincerts 里，这意味着掌握该签名私钥的人是 msp 的管理员。
		if err = x509Export(filepath.Join(mspDir, "admincerts", x509FileName(name)), cert); err != nil {
			return err
		}
	}

	tlsPrivateKey, err := csp.GeneratePrivateKey(tlsDir)
	if err != nil {
		return err
	}

	// 利用 TLS CA 为 admin 的公钥签署一份证书，并将该证书存储到 tls/name-cert.pem 文件中，但是在之后的代码中，该文件可能会被
	// 重命名为 tls/client.crt 或者 tls/server.crt
	if _, err = tlsCA.SignCertificate(
		tlsDir,
		name,
		nil,
		sans,
		&tlsPrivateKey.PublicKey,
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	); err != nil {
		return err
	}

	// 将 TLS CA 证书内容写入到 tls/ca.crt 文件中
	if err = x509Export(filepath.Join(tlsDir, "ca.crt"), tlsCA.SignCert); err != nil {
		return err
	}

	tlsFilePrefix := "server"
	if nodeType == CLIENT || nodeType == ADMIN {
		tlsFilePrefix = "client"
	}

	// 将 tls/name-cert.pem 重命名为 tls/client.crt 或者 tls/server.crt
	if err = os.Rename(filepath.Join(tlsDir, x509FileName(name)), filepath.Join(tlsDir, tlsFilePrefix+".crt")); err != nil {
		return err
	}

	// 将 tls/private_key 文件重命名为 tls/client.key 或者 tls/server.key
	if err = keyExport(tlsDir, filepath.Join(tlsDir, tlsFilePrefix+".key")); err != nil {
		return err
	}

	return nil
}

// GenerateVerifyingMSP 将 signCA 和 tlsCA 里的 x509 证书分别存储到 cacerts 和 tlscacerts 目录中，
// 然后随机生成一个 ECDSA 私钥，将私钥存储在 keystore 中 (以 ASN.1 DER PEM 格式存储)，然后利用
// signCA 里的 x509 证书对私钥的公钥签署生成公钥证书，作为 admin 的证书，存储在 admincerts 目中。
func GenerateVerifyingMSP(baseDir string, signCA, tlsCA *ca.CA, nodeOUs bool) error {
	// 创建存放 admin ca tls 证书的目录
	if err := createFolderStructure(baseDir, false); err != nil {
		return err
	}

	// 将 signCA 证书里 ASN.1 DER 编码的证书数据存储到 cacerts 目录中
	if err := x509Export(filepath.Join(baseDir, "cacerts", x509FileName(signCA.Name)), signCA.SignCert); err != nil {
		return err
	}

	// 将 tlsCA 证书里 ASN.1 DER 编码的证书数据存储到 tlscacerts 目录中
	if err := x509Export(filepath.Join(baseDir, "tlscacerts", x509FileName(tlsCA.Name)), tlsCA.SignCert); err != nil {
		return err
	}

	// 创建一个一次性证书作为管理员证书
	if nodeOUs {
		exportConfig(baseDir, "cacerts/"+x509FileName(signCA.Name), true)
	}

	ksDir := filepath.Join(baseDir, "keystore")
	if err := os.Mkdir(ksDir, os.FileMode(0755)); err != nil {
		return fmt.Errorf("failed to create keystore directory: [%s]", err.Error())
	}

	// 利用 ecdsa.GenerateKey(elliptic.P256(), rand.Reader) 方法随机生成一个私钥， 然后将该私钥转换为 ASN.1 DER PEM
	// 编码格式，存储到文件中，然后返回 *ecdsa.PrivateKey。
	privateKey, err := csp.GeneratePrivateKey(ksDir)
	if err != nil {
		return err
	}

	// 利用 ca 的证书为为刚刚生成的私钥的公钥签署生成一个证书，作为管理员的证书，但是在 fabric-samples 文件夹里，
	// admincerts 目录中是空的。
	if _, err := signCA.SignCertificate(filepath.Join(baseDir, "admincerts"), signCA.Name, nil, nil, &privateKey.PublicKey, x509.KeyUsageDigitalSignature, nil); err != nil {
		return err
	}

	return nil
}

/*** 🐋 ***/

// 内部函数

// createFolderStructure 创建三个目录：admincerts cacerts tlscacerts，如果传入的第二个参数 local 是 true，则
// 再创建两个目录：keystore signcerts。以上创建的目录与 exportConfig 函数创建的 config.yaml 文件在同一目录中。
func createFolderStructure(rootDir string, local bool) error {
	folders := []string{
		filepath.Join(rootDir, "admincerts"),
		filepath.Join(rootDir, "cacerts"),
		filepath.Join(rootDir, "tlscacerts"),
	}

	if local {
		// 如果是本地的，就把密钥的签名证书存储在本地
		folders = append(folders, filepath.Join(rootDir, "keystore"), filepath.Join(rootDir, "signcerts"))
	}

	for _, folder := range folders {
		if err := os.MkdirAll(folder, os.FileMode(0755)); err != nil {
			return err
		}
	}

	return nil
}

// x509FileName 将给定的字符串 name 和字符串 "-cert.pem" 前后拼接起来。
func x509FileName(name string) string {
	return name + "-cert.pem"
}

// x509Export 将 x509 证书里的内容 raw (ASN.1 DER 编码的数据) 编码成 PEM 格式的数据，然后再存储到指定位置。
func x509Export(path string, cert *x509.Certificate) error {
	return pemExport(path, "CERTIFICATE", cert.Raw)
}

// keyExport 将私钥从原先的地方移动到新的地址。
func keyExport(keystore, output string) error {
	return os.Rename(filepath.Join(keystore, "private_key"), output)
}

// pemExport 将 ASN.A DER 格式的数据编码成 PEM 格式，然后存储到指定位置。
func pemExport(path, pemType string, bz []byte) error {
	// 如果指定路径的文件不存在，就创建该文件，但是如果连目录都不存在，则会报错
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{Type: pemType, Bytes: bz})
}

// exportConfig 将配置信息存储到指定目录下：mspDir，并将文件命名为 "config.yaml"。配置文件里的内容大致如下所示：
//
//		NodeOUs:
//			Enable: true
//	 	ClientOUIdentifier:
//	   		Certificate: cacerts/ca.org1.example.com-cert.pem
//	   		OrganizationalUnitIdentifier: client
//	 	PeerOUIdentifier:
//	   		Certificate: cacerts/ca.org1.example.com-cert.pem
//	   		OrganizationalUnitIdentifier: peer
//	 	AdminOUIdentifier:
//	   		Certificate: cacerts/ca.org1.example.com-cert.pem
//	   		OrganizationalUnitIdentifier: admin
//	 	OrdererOUIdentifier:
//	   		Certificate: cacerts/ca.org1.example.com-cert.pem
//	   		OrganizationalUnitIdentifier: orderer
func exportConfig(mspDir, caFile string, enable bool) error {
	config := &hcmsp.Configuration{
		NodeOUs: &hcmsp.NodeOUs{
			Enable: enable,
			ClientOUIdentifier: &hcmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  caFile,
				OrganizationalUnitIdentifier: CLIENTOU,
			},
			PeerOUIdentifier: &hcmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  caFile,
				OrganizationalUnitIdentifier: PEEROU,
			},
			AdminOUIdentifier: &hcmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  caFile,
				OrganizationalUnitIdentifier: ADMINOU,
			},
			OrdererOUIdentifier: &hcmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  caFile,
				OrganizationalUnitIdentifier: ORDEREROU,
			},
		},
	}

	bz, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	// 如果指定路径的文件不存在，就创建该文件，但是如果连目录都不存在，则会报错
	file, err := os.Create(filepath.Join(mspDir, "config.yaml"))
	if err != nil {
		return err
	}

	defer file.Close()

	_, err = file.Write(bz)
	return err
}

/*** 🐋 ***/

// 为了单元测试
var ExportConfig = exportConfig
