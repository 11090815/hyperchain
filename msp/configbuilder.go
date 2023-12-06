package msp

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/11090815/hyperchain/bccsp"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

const (
	signcerts            = "signcerts"            // 定义存放签名证书的文件夹
	cacerts              = "cacerts"              // 定义存放 CA 证书的文件夹
	admincerts           = "admincerts"           // 定义存放管理员证书的文件夹
	intermediatecerts    = "intermediatecerts"    // 定义存放中级证书的文件夹
	tlscacerts           = "tlscacerts"           // 定义存放 TLS CA 证书的文件夹
	tlsintermediatecerts = "tlsintermediatecerts" // 定义存放 TLS 中级证书的文件夹
	crlsfolder           = "crls"                 // 定义存放被撤销的证书的文件夹
	keystore             = "keystore"             // 定义存放密钥的文件夹
	configFilename       = "config.yaml"          // 定义存放配置信息的文件
)

type Configuration struct {
	OrganizationalUnitIdentifiers []*OrganizationalUnitIdentifiersConfiguration `yaml:"OrganizationalUnitIdentifiers,omitempty"`
	NodeOUs                       *NodeOUs                                      `yaml:"NodeOUs,omitempty"`
}

// OrganizationalUnitIdentifiersConfiguration 用来代表一个 OU，OrganizationalUnitIdentifiersConfiguration 结构体内
// 有两个配置变量：Certificate 指向了存储根证书或者中间证书的路径；OrganizationalUnitIdentifier 代表 OU 的名字。
type OrganizationalUnitIdentifiersConfiguration struct {
	// Certificate 指向根证书或者中间证书的存放路径。
	Certificate string `yaml:"Certificate,omitempty"`
	// OrganizationalUnitIdentifier 是 OU 的名字，这没什么可说的。
	OrganizationalUnitIdentifier string `yaml:"OrganizationalUnitIdentifier,omitempty"`
}

// NodeOUs：
//   - ClientOUIdentifier 规定了如何通过 OU 识别 clients；
//   - PeerOUIdentifier 规定了如何通过 OU 识别 peers；
//   - AdminOUIdentifier 规定了如何通过 OU 识别 admins；
//   - OrdererOUIdentifier 规定了如何通过 OU 识别 orderers。
type NodeOUs struct {
	Enable bool `yaml:"Enable,omitempty"`
	// ClientOUIdentifier 规定了如何通过 OU 识别 clients。
	ClientOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"ClientOUIdentifier,omitempty"`
	// PeerOUIdentifier 规定了如何通过 OU 识别 peers。
	PeerOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"PeerOUIdentifier,omitempty"`
	// AdminOUIdentifier 规定了如何通过 OU 识别 admins。
	AdminOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"AdminOUIdentifier,omitempty"`
	// OrdererOUIdentifier 规定了如何通过 OU 识别 orderers。
	OrdererOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"OrdererOUIdentifier,omitempty"`
}

func GetLocalMSPConfigWithType(dir string, ID string, mspType string) (*pbmsp.MSPConfig, error) {
	switch mspType {
	case "bccsp":
		return GetLocalMSPConfig(dir, ID)
	default:
		return nil, fmt.Errorf("unknown MSP type [%s]", mspType)
	}
}

func GetLocalMSPConfig(dir string, ID string) (*pbmsp.MSPConfig, error) {
	signcertsDir := filepath.Join(dir, signcerts)
	keystoreDir := filepath.Join(dir, keystore) // 里面存储的密钥与 signcerts 里存储的证书是一一对应的。
	// 在这里提前设置好 KeyStore 的存储路径，将来调用 bccsp.NewFileBasedKeyStore 方法时，就不需要再传入路径参数了
	bccsp.PreSetKeyStorePath(keystoreDir)
	signCerts, err := getPEMMaterialFromDir(signcertsDir)
	if err != nil || len(signcertsDir) == 0 {
		return nil, fmt.Errorf("couldn't load a valid signer certificate from directory [%s]", dir)
	}

	signingIdentityInfo := &pbmsp.SigningIdentityInfo{
		PublicSigner:  signCerts[0],
		PrivateSigner: nil,
	}

	return getMSPConfig(dir, ID, signingIdentityInfo)
}

func getMSPConfig(dir string, id string, signingIdentityInfo *pbmsp.SigningIdentityInfo) (*pbmsp.MSPConfig, error) {
	cacertsDir := filepath.Join(dir, cacerts)
	admincertsDir := filepath.Join(dir, admincerts)
	intermediatecertsDir := filepath.Join(dir, intermediatecerts)
	crlsDir := filepath.Join(dir, crlsfolder)
	configFile := filepath.Join(dir, configFilename)
	tlscacertsDir := filepath.Join(dir, tlscacerts)
	tlsintermediatecertsDir := filepath.Join(dir, tlsintermediatecerts)

	cacertsPEM, err := getPEMMaterialFromDir(cacertsDir)
	if err != nil || len(cacertsPEM) == 0 {
		return nil, fmt.Errorf("couldn't load a valid ca certificate from directory [%s]", cacertsDir)
	}

	admincertsPEM, err := getPEMMaterialFromDir(admincertsDir)
	if err != nil || len(admincertsPEM) == 0 {
		if err != nil {
			return nil, fmt.Errorf("couldn't load a valid adminstrator certificate from directory [%s]: [%s]", cacertsDir, err.Error())
		}
		return nil, fmt.Errorf("couldn't load a valid adminstrator certificate from directory [%s]", cacertsDir)
	}

	intermediatecertsPEM, err := getPEMMaterialFromDir(intermediatecertsDir)
	if err != nil && os.IsNotExist(err) {
		mspLogger.Warnf("Intermediate certificate folder not found at [%s], skipping.", intermediatecertsDir)
	} else {
		return nil, fmt.Errorf("couldn't load a valid intermediate certificate from directory [%s]: [%s]", intermediatecertsDir, err.Error())
	}

	crlsPEM, err := getPEMMaterialFromDir(crlsDir)
	if err != nil && os.IsNotExist(err) {
		mspLogger.Warnf("revocated certificate list folder is not found at [%s]", crlsDir)
	} else if err != nil {
		return nil, fmt.Errorf("failed loading revocated certificates list at [%s]: [%s]", crlsDir, err.Error())
	}

	tlscacertsPEM, err := getPEMMaterialFromDir(tlscacertsDir)
	tlsintermediatecertsPEM := [][]byte{}
	if err != nil && os.IsNotExist(err) {
		mspLogger.Warnf("TLS CA certificates folder is not found at [%s].", tlscacertsDir)
	} else if err != nil {
		return nil, fmt.Errorf("failed loading tls ca certificates at [%s]: [%s]", tlscacertsDir, err.Error())
	} else if len(tlscacertsPEM) != 0 {
		tlsintermediatecertsPEM, err = getPEMMaterialFromDir(tlsintermediatecertsDir)
		if err != nil && os.IsNotExist(err) {
			mspLogger.Warnf("TLS intermediate certificates folder is not found at [%s].", tlsintermediatecertsDir)
		} else if err != nil {
			return nil, fmt.Errorf("failed loading TLS intermediate certificates at [%s]: [%s]", tlsintermediatecertsDir, err.Error())
		}
	} else {
		mspLogger.Warnf("TLS CA certificates folder is empty at [%s].", tlscacertsDir)
	}

	var organizationalUnitIdentifiers []*pbmsp.HyperchainOUIdentifier
	var nodeOrganizationalUnits *pbmsp.HyperchainNodeOUs
	_, err = os.Stat(configFile)
	if err == nil { // 判断文件存不存在
		raw, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed loading configuration file at [%s]: [%s]", configFile, err.Error())
		}
		configuration := Configuration{}
		if err = yaml.Unmarshal(raw, &configuration); err != nil {
			return nil, fmt.Errorf("failed loading configuration: [%s]", err.Error())
		}

		for _, organizationalUnitIdentifier := range configuration.OrganizationalUnitIdentifiers {
			certificatePath := filepath.Join(dir, organizationalUnitIdentifier.Certificate)
			raw, err = os.ReadFile(certificatePath)
			if err != nil {
				return nil, fmt.Errorf("failed loading organizational unit certificate at [%s]: [%s]", certificatePath, err.Error())
			}

			organizationalUnitIdentifiers = append(organizationalUnitIdentifiers, &pbmsp.HyperchainOUIdentifier{
				Certificate:                  raw,
				OrganizationalUnitIdentifier: organizationalUnitIdentifier.OrganizationalUnitIdentifier,
			})
		}

		if configuration.NodeOUs != nil && configuration.NodeOUs.Enable {
			nodeOrganizationalUnits = &pbmsp.HyperchainNodeOUs{Enable: true}
			if configuration.NodeOUs.ClientOUIdentifier != nil && len(configuration.NodeOUs.ClientOUIdentifier.OrganizationalUnitIdentifier) != 0 {
				nodeOrganizationalUnits.ClientOuIdentifier = &pbmsp.HyperchainOUIdentifier{OrganizationalUnitIdentifier: configuration.NodeOUs.ClientOUIdentifier.OrganizationalUnitIdentifier}
			}
			if configuration.NodeOUs.PeerOUIdentifier != nil && len(configuration.NodeOUs.PeerOUIdentifier.OrganizationalUnitIdentifier) != 0 {
				nodeOrganizationalUnits.PeerOuIdentifier = &pbmsp.HyperchainOUIdentifier{OrganizationalUnitIdentifier: configuration.NodeOUs.PeerOUIdentifier.OrganizationalUnitIdentifier}
			}
			if configuration.NodeOUs.AdminOUIdentifier != nil && len(configuration.NodeOUs.AdminOUIdentifier.OrganizationalUnitIdentifier) != 0 {
				nodeOrganizationalUnits.AdminOuIdentifier = &pbmsp.HyperchainOUIdentifier{OrganizationalUnitIdentifier: configuration.NodeOUs.AdminOUIdentifier.OrganizationalUnitIdentifier}
			}
			if configuration.NodeOUs.OrdererOUIdentifier != nil && len(configuration.NodeOUs.OrdererOUIdentifier.OrganizationalUnitIdentifier) != 0 {
				nodeOrganizationalUnits.OrdererOuIdentifier = &pbmsp.HyperchainOUIdentifier{OrganizationalUnitIdentifier: configuration.NodeOUs.OrdererOUIdentifier.OrganizationalUnitIdentifier}
			}

			if nodeOrganizationalUnits.ClientOuIdentifier != nil {
				nodeOrganizationalUnits.ClientOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.ClientOUIdentifier.Certificate, "ClientOU")
			}
			if nodeOrganizationalUnits.PeerOuIdentifier != nil {
				nodeOrganizationalUnits.PeerOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.PeerOUIdentifier.Certificate, "PeerOU")
			}
			if nodeOrganizationalUnits.OrdererOuIdentifier != nil {
				nodeOrganizationalUnits.OrdererOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.OrdererOUIdentifier.Certificate, "OrdererOU")
			}
			if nodeOrganizationalUnits.AdminOuIdentifier != nil {
				nodeOrganizationalUnits.AdminOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.AdminOUIdentifier.Certificate, "AdminOU")
			}
		}
	} else {
		return nil, fmt.Errorf("failed loading configuration file at [%s]: [%s]", configFile, err.Error())
	}

	cryptoConfig := &pbmsp.HyperchainCryptoConfig{
		HashAlgorithm: bccsp.SHA256,
	}

	mspConfig := &pbmsp.HyperchainMSPConfig{
		Admins:                        admincertsPEM,
		RootCerts:                     cacertsPEM,
		IntermediateCerts:             intermediatecertsPEM,
		SigningIdentity:               signingIdentityInfo,
		Name:                          id,
		OrganizationalUnitIdentifiers: organizationalUnitIdentifiers,
		RevocationList:                crlsPEM,
		CryptoConfig:                  cryptoConfig,
		TlsRootCerts:                  tlscacertsPEM,
		TlsIntermediateCerts:          tlsintermediatecertsPEM,
		HyperchainNodeOus:             nodeOrganizationalUnits,
	}

	raw, err := proto.Marshal(mspConfig)
	if err != nil {
		return nil, err
	}

	return &pbmsp.MSPConfig{
		Config: raw,
		Type:   int32(HYPERCHAIN),
	}, nil
}

// getPEMMaterialFromDir 从给定的目录中将所有 pem 格式编码的数据材料读取出来。
func getPEMMaterialFromDir(dir string) ([][]byte, error) {
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil, err
	}

	materials := make([][]byte, 0)
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed getting PEM materials: [%s]", err.Error())
	}

	for _, f := range files {
		filePath := filepath.Join(dir, f.Name())

		stat, err := os.Stat(filePath)
		if err != nil {
			mspLogger.Errorf("Failed to get file info on [%s]: [%s]", filePath, err.Error())
			continue
		}

		if stat.IsDir() {
			mspLogger.Warnf("There should only be files, not directories in [%s].", dir)
			continue
		}

		material, err := os.ReadFile(filePath)
		if err != nil {
			mspLogger.Warnf("Failed reading from file [%s]: [%s].", filePath, err.Error())
			continue
		}
		block, _ := pem.Decode(material)
		if block == nil {
			mspLogger.Warnf("Not PEM format material in file [%s].", filePath)
			continue
		}

		materials = append(materials, material)
	}

	return materials, nil
}

func loadCertificateAt(dir string, certificatePath string, ouType string) []byte {
	path := filepath.Join(dir, certificatePath)
	raw, err := os.ReadFile(path)
	if err != nil {
		mspLogger.Errorf("Failed loading [%s] type certificate at [%s]: [%s].", ouType, path, err.Error())
		return nil
	} else {
		return raw
	}
}
