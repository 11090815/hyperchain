package tlsgen

/*

一些注释参考网址：https://foreverz.cn/go-cert

*/

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

type CertKeyPair struct {
	// cert 是 pem 格式编码的证书。
	// 一般先把密钥转换为 DER 格式，再把 DER 格式的数据转换为 PEM 格式。
	cert []byte

	// key 是与 Cert 对应的密钥，按照 pem 格式编码。
	key []byte

	// Signer 其实就是 *ecdsa.PrivateKey，它代表着给 TLSCert 证书签名背书的节点。
	endorser crypto.Signer

	// x509Cert 与 Cert 其实是一个东西，因为 x509Cert 其实是通过以下步骤对 Cert 进行转换得到的：
	//	1: block, _ := pem.Decode(Cert)
	//	2: x509Cert, _ := x509.ParseCertificate(block.Bytes)
	x509Cert *x509.Certificate
}

// PublicKeyDER x509 公钥证书的 ASN.1 DER 编码格式。
func (ckp *CertKeyPair) PublicKeyDER() []byte {
	raw := make([]byte, len(ckp.x509Cert.Raw))
	copy(raw, ckp.x509Cert.Raw)
	return raw
}

// PublicKeyPEM x509 公钥证书的 ASN.1 DER PEM 编码格式。
func (ckp *CertKeyPair) PublicKeyPEM() []byte {
	pem := make([]byte, len(ckp.cert))
	copy(pem, ckp.cert)
	return pem
}

func (ckp *CertKeyPair) PrivateKeyPEM() []byte {
	pem := make([]byte, len(ckp.key))
	copy(pem, ckp.key)
	return pem
}

func newCertKeyPair(isCA bool, isServer bool, certSigner crypto.Signer, parent *x509.Certificate, hosts ...string) (*CertKeyPair, error) {
	privateKey, privateKeyBytes, err := newPrivateKey()
	if err != nil {
		return nil, err
	}

	template, err := newCertTemplate()
	if err != nil {
		return nil, err
	}

	tenYearsFromNow := time.Now().Add(time.Hour * 24 * 365 * 10)

	if isCA {
		// 为证书颁发中心 CA 生成证书和密钥
		template.NotAfter = tenYearsFromNow
		template.IsCA = true
		template.KeyUsage = template.KeyUsage | x509.KeyUsageCertSign | x509.KeyUsageCRLSign              // 用于校验公钥证书的签名 | 用于验证证书吊销列表的签名
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} // 建立TLS连接时进行客户端验证 | 建立TLS连接时进行服务器身份验证
		template.BasicConstraintsValid = true                                                             // 表示IsCA/MaxPathLen/MaxPathLenZero有效
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} // 非 CA 证书，建立 TLS 连接时，仅进行客户端验证
	}

	if isServer {
		template.NotAfter = tenYearsFromNow
		// 如果不添加 x509.ExtKeyUsageServerAuth 标志位的话，在验证客户端证书时会报错：tls: failed to verify certificate: x509: certificate specifies an incompatible key usage
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth) // 服务器的证书，建立 TLS 连接时，既进行客户端验证，也进行服务器身份验证
		for _, host := range hosts {
			if ip := net.ParseIP(host); ip != nil {
				// IPAddresses 里必须含有服务端正在监听的 IP 地址
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, host)
			}
		}
	}

	hash := sha256.New()
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	hash.Write(publicKeyBytes)
	template.SubjectKeyId = hash.Sum(nil)

	if parent == nil || certSigner == nil {
		// 自己给自己签名的证书
		parent = &template
		certSigner = privateKey
	}

	// 证书由父级证书签名。如果父级证书等于模板，则证书为自签名。参数 pub 是要生成证书的公钥，priv 是签名者的私钥。
	raw, err := x509.CreateCertificate(rand.Reader, &template, parent, &privateKey.PublicKey, certSigner)
	if err != nil {
		return nil, err
	}
	publicKeyDERPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})

	tlsCert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}

	privateKeyDERPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})

	return &CertKeyPair{
		cert:     publicKeyDERPEM,
		key:      privateKeyDERPEM,
		endorser: privateKey,
		x509Cert: tlsCert,
	}, nil
}

func newCertTemplate() (x509.Certificate, error) {
	serialNum, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return x509.Certificate{}, err
	}

	return x509.Certificate{
		Subject:      pkix.Name{SerialNumber: serialNum.String()},                  // 证书持有者的信息
		NotBefore:    time.Now().Add(time.Hour * (-24)),                            // 证书有效期开始时间不要早于一天前
		NotAfter:     time.Now().Add(time.Hour * 24),                               // 证书过期时间不要晚于一天后
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, // 定义了证书包含的密钥的用途：加密对称密钥 | 数字签名
		SerialNumber: serialNum,                                                    // 证书序列号，标识证书的唯一整数，重复的编号无法安装到系统里
	}, nil
}

// newPrivateKey 新建一个 P256 椭圆曲线上的私钥，然后将该私钥转换为 PKCS#8 ASN.1 DER 格式。
func newPrivateKey() (privateKey *ecdsa.PrivateKey, privateKeyBytes []byte, err error) {
	if privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, nil, err
	}

	if privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(privateKey); err != nil {
		return nil, nil, err
	}

	return privateKey, privateKeyBytes, nil
}
