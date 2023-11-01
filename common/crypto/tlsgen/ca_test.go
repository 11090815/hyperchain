package tlsgen

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func createTLSService(t *testing.T, ca *CA, host string) *grpc.Server {
	certKeyPair, err := ca.NewServerCertKeyPair(host)
	require.NoError(t, err)
	certificate, err := tls.X509KeyPair(certKeyPair.cert, certKeyPair.key)
	require.NoError(t, err)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    x509.NewCertPool(), // 用来验证客户端身份的一组根证书颁发机构
	}

	// 利用根 CA 的证书验证客户端的身份
	tlsConf.ClientCAs.AppendCertsFromPEM(ca.CertBytes())
	return grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConf)))
}

func TestTLSCA(t *testing.T) {
	// 创建一个根 CA
	ca, err := NewCA()
	require.NoError(t, err)

	// 利用根 CA 给服务端创建 TLS 证书，然后开启服务端的 TLS 连接
	server := createTLSService(t, ca, "127.0.0.1")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go server.Serve(listener)
	defer server.Stop()
	defer listener.Close()

	probeTLS := func(certKeyPair *CertKeyPair) error {
		certificate, err := tls.X509KeyPair(certKeyPair.cert, certKeyPair.key)
		require.NoError(t, err)
		tlsConf := &tls.Config{
			RootCAs:      x509.NewCertPool(),
			Certificates: []tls.Certificate{certificate}, // 用于出示给对方的证书
		}
		tlsConf.RootCAs.AppendCertsFromPEM(ca.CertBytes()) // 利用根 CA 的证书验证服务端的身份
		tlsOpts := grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := grpc.DialContext(ctx, listener.Addr().String(), tlsOpts, grpc.WithBlock())
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}

	// 利用根 CA 给客户端创建 TLS 证书，然后让客户端与服务端建立 TLS 连接
	clientCertKeyPair, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)
	err = probeTLS(clientCertKeyPair)
	require.NoError(t, err)

	// 创建另一个根 CA，然后基于该 CA 创建一个客户端的 TLS 证书，然后该客户端尝试连接之前的根 CA 创建的服务端，连接会失败
	otherCA, _ := NewCA()
	clientCertKeyPair, err = otherCA.NewClientCertKeyPair()
	require.NoError(t, err)
	err = probeTLS(clientCertKeyPair)
	require.Error(t, err)
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
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	return template, nil
}

func TestUseCertificate(t *testing.T) {
	template, err := x509Template()
	require.NoError(t, err)

	template.IsCA = true

	key, err := genECDSAKey("nwpu")
	require.NoError(t, err)

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	certFile, err := os.Create("nwpu-cert.pem")
	require.NoError(t, err)

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	require.NoError(t, err)

	// 用证书验证签名
	msg := []byte("hello, world")
	digest := sha256.Sum256(msg)

	sig, err := key.Sign(rand.Reader, digest[:], nil)
	require.NoError(t, err)

	err = cert.CheckSignature(x509.ECDSAWithSHA256, msg, sig)
	require.NoError(t, err)

	// 用父级证书验证子证书
	childKey, err := genECDSAKey("nwpu-child")
	require.NoError(t, err)

	template, err = x509Template()
	require.NoError(t, err)
	childCertBytes, err := x509.CreateCertificate(rand.Reader, &template, cert, &childKey.PublicKey, key)
	require.NoError(t, err)

	childCertFile, err := os.Create("nwpu-child-cert.pem")
	require.NoError(t, err)

	err = pem.Encode(childCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: childCertBytes})
	require.NoError(t, err)

	childCert, err := x509.ParseCertificate(childCertBytes)
	require.NoError(t, err)

	err = childCert.CheckSignatureFrom(cert)
	require.NoError(t, err)
}
