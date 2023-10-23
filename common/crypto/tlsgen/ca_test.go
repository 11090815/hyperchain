package tlsgen

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
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
