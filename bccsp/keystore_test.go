package bccsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/stretchr/testify/require"
)

func TestFileMode(t *testing.T) {
	t.Log(os.ModeAppend | os.ModeCharDevice | os.ModeDir)
	t.Log(os.ModeTemporary)
	t.Log(os.FileMode(0755))
}

func TestStoreAndLoad(t *testing.T) {
	hlogging.Init(hlogging.Config{Format: hlogging.ShortFuncFormat})
	hlogging.ActivateSpec("bccsp_ks=debug")

	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "bccspks")
	fmt.Println("path:", path)

	ks, err := NewFileBasedKeyStore(path, false)
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pk := &ecdsaPublicKey{publicKey: &privateKey.PublicKey}
	sk := &ecdsaPrivateKey{privateKey: privateKey}

	err = ks.StoreKey(pk)
	require.NoError(t, err)

	err = ks.StoreKey(sk)
	require.NoError(t, err)

	files, err := os.ReadDir(path)
	require.NoError(t, err)

	for _, f := range files {
		if strings.HasSuffix(f.Name(), "public_key") {
			fmt.Println("public key:", f.Name())
			index := strings.LastIndex(f.Name(), "_")
			fmt.Println("ski of public:", f.Name()[:index])
			fmt.Println()
		} else if strings.HasSuffix(f.Name(), "private_key") {
			fmt.Println("private key:", f.Name())
			index := strings.LastIndex(f.Name(), "_")
			fmt.Println("ski of private:", f.Name()[:index])
			fmt.Println()
		}
	}

	key, err := ks.GetKey(pk.SKI())
	require.NoError(t, err)

	switch key.(type) {
	case *ecdsaPrivateKey:
		fmt.Println("get a private key")
	case *ecdsaPublicKey:
		fmt.Println("get a public key")
	default:
		fmt.Println("unknown key type")
	}
}

func TestStore(t *testing.T) {
	hlogging.ActivateSpec("bccsp_ks=debug")

	path, _ := os.Getwd()
	path = filepath.Join(path, "testdata")

	ks, err := NewFileBasedKeyStore(path, false)
	require.NoError(t, err)

	aesRaw, err := GetRandomBytes(32)
	require.NoError(t, err)
	aesK := &aesKey{key: aesRaw}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdsaSK := &ecdsaPrivateKey{privateKey: privateKey}
	ecdsaPK := &ecdsaPublicKey{publicKey: &privateKey.PublicKey}

	err = ks.StoreKey(aesK)
	require.NoError(t, err)

	err = ks.StoreKey(ecdsaPK)
	require.NoError(t, err)

	err = ks.StoreKey(ecdsaSK)
	require.NoError(t, err)
}

func TestData(t *testing.T) {
	path, _ := os.Getwd()
	path = filepath.Join(path, "testdata")

	ks, err := NewFileBasedKeyStore(path, false)
	require.NoError(t, err)

	files, err := os.ReadDir(path)
	require.NoError(t, err)

	skis := make(map[string]struct{})

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		index := strings.Index(f.Name(), "_")
		if index == -1 {
			continue
		}
		skis[f.Name()[:index]] = struct{}{}
	}

	for ski, _ := range skis {
		ski, _ := hex.DecodeString(ski)

		key, err := ks.GetKey(ski)
		require.NoError(t, err)

		switch key.(type) {
		case *ecdsaPrivateKey:
			fmt.Println("ecdsa private key")
		case *ecdsaPublicKey:
			fmt.Println("ecdsa public key")
		case *aesKey:
			fmt.Println("aes key")
		default:
			fmt.Printf("unknown key type [%T]\n", key)
		}
	}
}

func TestStoreKeyAndCertificate(t *testing.T) {
	ks, err := NewFileBasedKeyStore("testdata", false)
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sk := &ecdsaPrivateKey{privateKey: privateKey}
	err = ks.StoreKey(sk)
	require.NoError(t, err)

	cert, err := newCert(privateKey)
	require.NoError(t, err)
	f, err := os.OpenFile("testdata/cert.pem", os.O_CREATE|os.O_RDWR, os.FileMode(0600))
	require.NoError(t, err)
	f.Write(cert)
	f.Close()
}

func newCert(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	template, err := newCertTemplate()
	if err != nil {
		return nil, err
	}

	tenYearsFromNow := time.Now().Add(time.Hour * 24 * 365 * 10)

	// 为证书颁发中心 CA 生成证书和密钥
	template.NotAfter = tenYearsFromNow

	hash := sha256.New()
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	hash.Write(publicKeyBytes)
	template.SubjectKeyId = hash.Sum(nil)

	// 证书由父级证书签名。如果父级证书等于模板，则证书为自签名。参数 pub 是要生成证书的公钥，priv 是签名者的私钥。
	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	publicKeyDERPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	return publicKeyDERPEM, nil
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
