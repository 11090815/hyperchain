package comm_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/common/crypto/tlsgen"
	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/internal/pkg/comm"
	"github.com/11090815/hyperchain/internal/pkg/comm/testdata/protobuf"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type org struct {
	publicKeyPEM  []byte
	privateKeyPEM []byte
	cert          tls.Certificate
	serverCerts   []serverCert
	clientCerts   []clientCert
	childOrgs     []org
}

type serverCert struct {
	publicKeyPEM  []byte
	privateKeyPEM []byte
	cert          tls.Certificate
}

type clientCert struct {
	publicKeyPEM  []byte
	privateKeyPEM []byte
	cert          tls.Certificate
}

type server struct {
	config comm.ServerConfig
}

type client struct {
	config comm.ClientConfig
}

func (o *org) servers(clientRootCAs [][]byte) []server {
	clientRootCAs = append(clientRootCAs, o.publicKeyPEM)

	ss := make([]server, 0)

	for _, sc := range o.serverCerts {
		s := server{
			config: comm.ServerConfig{
				ConnectionTimeout: timeout,
				SecureOptions: comm.SecureOptions{
					UseTLS:            true,
					PublicKeyPEM:      sc.publicKeyPEM,
					PrivateKeyPEM:     sc.privateKeyPEM,
					RequireClientCert: true,
					ClientRootCAs:     clientRootCAs,
				},
			},
		}
		ss = append(ss, s)
	}

	return ss
}

func (o *org) clients(serverRootCAs [][]byte) []client {
	serverRootCAs = append(serverRootCAs, o.publicKeyPEM)

	cs := make([]client, 0)
	for _, cc := range o.clientCerts {
		c := client{
			config: comm.ClientConfig{
				DialTimeout: timeout,
				SecureOptions: comm.SecureOptions{
					ServerRootCAs:     serverRootCAs,
					UseTLS:            true,
					PublicKeyPEM:      cc.publicKeyPEM,
					PrivateKeyPEM:     cc.privateKeyPEM,
					RequireClientCert: true,
				},
			},
		}
		cs = append(cs, c)
	}

	return cs
}

func loadOrg(parent, child int, isIntermediate bool) (*org, error) {
	o := &org{}
	var err error
	var intermediate *org

	if !isIntermediate {
		if o.publicKeyPEM, err = os.ReadFile(filepath.Join("testdata", "certs", fmt.Sprintf("nwpu-%d-cert.pem", parent))); err != nil {
			return nil, err
		}
		if o.privateKeyPEM, err = os.ReadFile(filepath.Join("testdata", "certs", fmt.Sprintf("nwpu-%d-key.pem", parent))); err != nil {
			return nil, err
		}
	} else {
		if o.publicKeyPEM, err = os.ReadFile(filepath.Join("testdata", "certs", fmt.Sprintf("nwpu-%d-intermediate-%d-cert.pem", parent, child))); err != nil {
			return nil, err
		}
		if o.privateKeyPEM, err = os.ReadFile(filepath.Join("testdata", "certs", fmt.Sprintf("nwpu-%d-intermediate-%d-key.pem", parent, child))); err != nil {
			return nil, err
		}
	}
	if o.cert, err = tls.X509KeyPair(o.publicKeyPEM, o.privateKeyPEM); err != nil {
		return nil, err
	}

	for i := 1; i <= 2; i++ {
		sc := serverCert{}
		if !isIntermediate {
			if sc.publicKeyPEM, err = os.ReadFile(filepath.Join("testdata", "certs", fmt.Sprintf("nwpu-%d-server-%d-cert.pem", parent, i))); err != nil {
				return nil, err
			}
			if sc.privateKeyPEM, err = os.ReadFile(filepath.Join("testdata", "certs", fmt.Sprintf("nwpu-%d-server-%d-key.pem", parent, i))); err != nil {
				return nil, err
			}
		} else {
			if sc.publicKeyPEM, err = os.ReadFile(filepath.Join("testdata", "certs", fmt.Sprintf("nwpu-%d-intermediate-%d-server-%d-cert.pem", parent, child, i))); err != nil {
				return nil, err
			}
			if sc.privateKeyPEM, err = os.ReadFile(filepath.Join("testdata", "certs", fmt.Sprintf("nwpu-%d-intermediate-%d-server-%d-key.pem", parent, child, i))); err != nil {
				return nil, err
			}
		}

		if sc.cert, err = tls.X509KeyPair(sc.publicKeyPEM, sc.privateKeyPEM); err != nil {
			return nil, err
		}
		o.serverCerts = append(o.serverCerts, sc)
	}

	for i := 1; i <= 2; i++ {
		cc := clientCert{}
		if !isIntermediate {
			if cc.publicKeyPEM, err = os.ReadFile(filepath.Join("testdata", "certs", fmt.Sprintf("nwpu-%d-client-%d-cert.pem", parent, i))); err != nil {
				return nil, err
			}
			if cc.privateKeyPEM, err = os.ReadFile(filepath.Join("testdata", "certs", fmt.Sprintf("nwpu-%d-client-%d-key.pem", parent, i))); err != nil {
				return nil, err
			}
		} else {
			if cc.publicKeyPEM, err = os.ReadFile(filepath.Join("testdata", "certs", fmt.Sprintf("nwpu-%d-intermediate-%d-client-%d-cert.pem", parent, child, i))); err != nil {
				return nil, err
			}
			if cc.privateKeyPEM, err = os.ReadFile(filepath.Join("testdata", "certs", fmt.Sprintf("nwpu-%d-intermediate-%d-client-%d-key.pem", parent, child, i))); err != nil {
				return nil, err
			}
		}
		if cc.cert, err = tls.X509KeyPair(cc.publicKeyPEM, cc.privateKeyPEM); err != nil {
			return nil, err
		}
		o.clientCerts = append(o.clientCerts, cc)
	}

	if isIntermediate {
		return o, nil
	}

	for i := 1; i <= 2; i++ {
		if intermediate, err = loadOrg(parent, i, true); err != nil {
			return nil, err
		}
		o.childOrgs = append(o.childOrgs, *intermediate)
	}

	return o, nil
}

func TestLoadOrg(t *testing.T) {
	o, err := loadOrg(1, 0, false)
	require.NoError(t, err)

	require.Len(t, o.clientCerts, 2)
	require.Len(t, o.serverCerts, 2)
	require.Len(t, o.childOrgs, 2)
}

func TestNewGRPCServerInvalidParams(t *testing.T) {
	org, err := loadOrg(1, 0, false)
	require.NoError(t, err)

	_, err = comm.NewGRPCServer("", comm.ServerConfig{})
	require.ErrorContains(t, err, "missing address")

	_, err = comm.NewGRPCServer("abcdef", comm.ServerConfig{})
	require.ErrorContains(t, err, "missing port in address")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	_, err = comm.NewGRPCServerFromListener(listener, comm.ServerConfig{})
	require.NoError(t, err)

	_, err = comm.NewGRPCServerFromListener(listener, comm.ServerConfig{
		SecureOptions: comm.SecureOptions{
			UseTLS:        true,
			PublicKeyPEM:  []byte{},
			PrivateKeyPEM: org.privateKeyPEM,
		},
	})
	require.ErrorContains(t, err, "tls: failed to find any PEM data in certificate input")
}

func TestNewInsecureGRPCServer(t *testing.T) {
	address := "127.0.0.1:9253"
	s, err := comm.NewGRPCServer(address, comm.ServerConfig{
		SecureOptions: comm.SecureOptions{UseTLS: false},
	})
	require.NoError(t, err)

	addr, err := net.ResolveTCPAddr("tcp", address)
	require.NoError(t, err)
	require.Equal(t, s.Address(), addr.String())

	require.False(t, s.TLSEnabled())
	require.False(t, s.MutualTLSRequired())

	key, _ := bccsp.GetRandomBytes(32)
	protobuf.RegisterEncryptorDecryptorServer(s.Server(), &edserver{key: key})
	go s.Start()
	defer s.Stop()

	time.Sleep(time.Millisecond * 10)

	conn, err := grpc.Dial(address, grpc.WithInsecure())
	require.NoError(t, err)
	client := protobuf.NewEncryptorDecryptorClient(conn)
	reply, err := client.Encrypt(context.Background(), &protobuf.Request{Plaintext: []byte("hello, golang")})
	require.NoError(t, err)
	require.NotNil(t, reply)
}

func TestNewSecureGRPCServer(t *testing.T) {
	org, err := loadOrg(1, 0, false)
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	address := listener.Addr().String()

	server, err := comm.NewGRPCServerFromListener(listener, comm.ServerConfig{
		ConnectionTimeout: timeout,
		SecureOptions: comm.SecureOptions{
			UseTLS:            true,
			PublicKeyPEM:      org.serverCerts[0].publicKeyPEM,
			PrivateKeyPEM:     org.serverCerts[0].privateKeyPEM,
			RequireClientCert: true,
			ClientRootCAs:     [][]byte{org.publicKeyPEM},
		},
		Logger: hlogging.MustGetLogger("grpc_server"),
	})
	require.NoError(t, err)

	key, _ := bccsp.GetRandomBytes(32)
	go server.Start()
	defer server.Stop()
	protobuf.RegisterEncryptorDecryptorServer(server.Server(), &edserver{key: key})

	clientConfig := comm.ClientConfig{
		DialTimeout: timeout,
		SecureOptions: comm.SecureOptions{
			UseTLS:            true,
			PublicKeyPEM:      org.clientCerts[0].publicKeyPEM,
			PrivateKeyPEM:     org.clientCerts[0].privateKeyPEM,
			RequireClientCert: true,
			ServerRootCAs:     [][]byte{org.publicKeyPEM},
		},
	}
	conn, err := clientConfig.Dial(address)
	require.NoError(t, err)

	client := protobuf.NewEncryptorDecryptorClient(conn)

	reply, err := client.Encrypt(context.Background(), &protobuf.Request{Plaintext: []byte("grpc")})
	require.NoError(t, err)
	require.NotNil(t, reply)
}

func TestNewSecureGRPCServerWithCredentials(t *testing.T) {
	org, err := loadOrg(1, 0, false)
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	defer listener.Close()

	server, err := comm.NewGRPCServerFromListener(listener, comm.ServerConfig{
		ConnectionTimeout: timeout,
		SecureOptions: comm.SecureOptions{
			UseTLS:        true,
			PublicKeyPEM:  org.serverCerts[0].publicKeyPEM,
			PrivateKeyPEM: org.serverCerts[0].privateKeyPEM,
		},
	})
	require.NoError(t, err)
	go server.Start()
	defer server.Stop()

	t.Log(server.Address())

	key, _ := bccsp.GetRandomBytes(32)
	protobuf.RegisterEncryptorDecryptorServer(server.Server(), &edserver{key: key})

	// 创建凭证
	certPool := x509.NewCertPool()
	// certPool.AppendCertsFromPEM(org.serverCerts[1].publicKeyPEM)
	certPool.AppendCertsFromPEM(org.serverCerts[0].publicKeyPEM)
	creds := credentials.NewClientTLSFromCert(certPool, "")

	// 创建客户端
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := grpc.DialContext(ctx, address, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	client := protobuf.NewEncryptorDecryptorClient(conn)

	// 调用方法
	reply, err := client.Encrypt(ctx, &protobuf.Request{Plaintext: []byte("hello")})
	require.NoError(t, err)
	require.NotNil(t, reply)
}

func TestVerifyCertificateCallback(t *testing.T) {
	ca, err := tlsgen.NewCA()
	require.NoError(t, err)

	authorizedClientCertKeyPair, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)

	notAuthorizedClientCertKeyPair, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)

	serverKeyPair, err := ca.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)

	verifyFunc := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if bytes.Equal(rawCerts[0], authorizedClientCertKeyPair.PublicKeyDER()) {
			return nil
		}
		return errors.New("client certificate mismatch")
	}

	probeTLS := func(endpoint string, clientKeyPair *tlsgen.CertKeyPair) error {
		cert, err := tls.X509KeyPair(clientKeyPair.PublicKeyPEM(), clientKeyPair.PrivateKeyPEM())
		if err != nil {
			return err
		}
		tlsCfg := &tls.Config{
			RootCAs:      x509.NewCertPool(),
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		}
		tlsCfg.RootCAs.AppendCertsFromPEM(ca.CertBytes())
		conn, err := tls.Dial("tcp", endpoint, tlsCfg)
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}

	server, err := comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{
		ConnectionTimeout: timeout,
		SecureOptions: comm.SecureOptions{
			VerifyCertificate: verifyFunc,
			ClientRootCAs:     [][]byte{ca.CertBytes()},
			RequireClientCert: true,
			UseTLS:            true,
			PublicKeyPEM:      serverKeyPair.PublicKeyPEM(),
			PrivateKeyPEM:     serverKeyPair.PrivateKeyPEM(),
		},
	})
	require.NoError(t, err)

	go server.Start()
	defer server.Stop()

	err = probeTLS(server.Address(), authorizedClientCertKeyPair)
	require.NoError(t, err)

	err = probeTLS(server.Address(), notAuthorizedClientCertKeyPair)
	require.Error(t, err)
}

func TestWithSignedRootCertificates(t *testing.T) {
	serverCertPEM, err := os.ReadFile(filepath.Join("testdata", "certs", "nwpu-1-server-1-cert.pem"))
	require.NoError(t, err)

	serverKeyPEM, err := os.ReadFile(filepath.Join("testdata", "certs", "nwpu-1-server-1-key.pem"))
	require.NoError(t, err)

	caCertPEM, err := os.ReadFile(filepath.Join("testdata", "certs", "nwpu-1-cert.pem"))
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	defer listener.Close()

	server, err := comm.NewGRPCServerFromListener(listener, comm.ServerConfig{
		SecureOptions: comm.SecureOptions{
			UseTLS:        true,
			PublicKeyPEM:  serverCertPEM,
			PrivateKeyPEM: serverKeyPEM,
		},
	})
	require.NoError(t, err)
	key, _ := bccsp.GetRandomBytes(32)
	protobuf.RegisterEncryptorDecryptorServer(server.Server(), &edserver{key: key})
	go server.Start()
	defer server.Stop()

	time.Sleep(time.Millisecond * 10)

	// 利用服务端的证书作为凭证
	certPoolServer := x509.NewCertPool()
	certPoolServer.AppendCertsFromPEM(serverCertPEM)
	creds := credentials.NewClientTLSFromCert(certPoolServer, "")
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	client := protobuf.NewEncryptorDecryptorClient(conn)
	res, err := client.Encrypt(context.Background(), &protobuf.Request{Plaintext: []byte("我是一名Go开发者")})
	require.NoError(t, err)
	fmt.Printf("加密结果：%x\n", res.Ciphertext)

	// 利用 CA 的证书作为凭证
	certPoolCA := x509.NewCertPool()
	certPoolCA.AppendCertsFromPEM(caCertPEM)
	creds = credentials.NewClientTLSFromCert(certPoolCA, "")
	conn, err = grpc.Dial(address, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	client = protobuf.NewEncryptorDecryptorClient(conn)
	res, err = client.Encrypt(context.Background(), &protobuf.Request{Plaintext: []byte("我是一名Java开发者")})
	require.NoError(t, err)
	fmt.Printf("加密结果：%x\n", res.Ciphertext)
}

func TestWithIntermediateCertificate(t *testing.T) {
	serverCertPEM, _ := os.ReadFile(filepath.Join("testdata", "certs", "nwpu-1-intermediate-1-server-1-cert.pem"))
	serverKeyPEM, _ := os.ReadFile(filepath.Join("testdata", "certs", "nwpu-1-intermediate-1-server-1-key.pem"))

	intermediateCACertPEM, _ := os.ReadFile(filepath.Join("testdata", "certs", "nwpu-1-intermediate-1-cert.pem"))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	defer listener.Close()

	server, err := comm.NewGRPCServerFromListener(listener, comm.ServerConfig{
		SecureOptions: comm.SecureOptions{
			UseTLS:        true,
			PublicKeyPEM:  serverCertPEM,
			PrivateKeyPEM: serverKeyPEM,
		},
	})
	require.NoError(t, err)
	key, _ := bccsp.GetRandomBytes(32)
	protobuf.RegisterEncryptorDecryptorServer(server.Server(), &edserver{key: key})
	go server.Start()
	defer server.Stop()

	time.Sleep(time.Millisecond * 10)

	// 利用服务端的证书作为凭证
	certPoolServer := x509.NewCertPool()
	certPoolServer.AppendCertsFromPEM(serverCertPEM)
	creds := credentials.NewClientTLSFromCert(certPoolServer, "")
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	client := protobuf.NewEncryptorDecryptorClient(conn)
	res, err := client.Encrypt(context.Background(), &protobuf.Request{Plaintext: []byte("我是一名Go开发者，Go是一门特别有趣的编成语言！")})
	require.NoError(t, err)
	fmt.Printf("加密结果：%x\n", res.Ciphertext)

	// 利用中级 CA 的证书作为凭证
	certPoolCA := x509.NewCertPool()
	certPoolCA.AppendCertsFromPEM(intermediateCACertPEM)
	creds = credentials.NewClientTLSFromCert(certPoolCA, "")
	conn, err = grpc.Dial(address, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	client = protobuf.NewEncryptorDecryptorClient(conn)
	res, err = client.Encrypt(context.Background(), &protobuf.Request{Plaintext: []byte("我是一名Java开发者")})
	require.NoError(t, err)
	fmt.Printf("加密结果：%x\n", res.Ciphertext)
}

func runMutualAuth(t *testing.T, servers []server, trustedClients, untrustedClients []client) error {
	for i := 0; i < len(servers); i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		address := listener.Addr().String()
		defer listener.Close()

		gRPCServer, err := comm.NewGRPCServerFromListener(listener, servers[i].config)
		if err != nil {
			return err
		}

		require.True(t, gRPCServer.MutualTLSRequired())

		key, _ := bccsp.GetRandomBytes(32)
		protobuf.RegisterEncryptorDecryptorServer(gRPCServer.Server(), &edserver{key: key})
		go gRPCServer.Start()
		defer gRPCServer.Stop()

		time.Sleep(time.Millisecond * 10)

		for j := 0; j < len(trustedClients); j++ {
			tlsCfg, _ := trustedClients[j].config.SecureOptions.ToTLSConfig()
			creds := grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
			conn, err := grpc.Dial(address, creds)
			if err != nil {
				return err
			}
			client := protobuf.NewEncryptorDecryptorClient(conn)
			res, err := client.Encrypt(context.Background(), &protobuf.Request{Plaintext: []byte(fmt.Sprintf("hello, i am no.%d client.", j))})
			if err != nil {
				return err
			}
			fmt.Printf("Encrypted server %d client %d: %x\n", i, j, res.Ciphertext)
		}

		for k := 0; k < len(untrustedClients); k++ {
			tlsCfg, _ := untrustedClients[k].config.SecureOptions.ToTLSConfig()
			_, err := tls.Dial("tcp", address, tlsCfg)
			if err != nil {
				t.Logf("Untrusted client%d was correctly rejected by %s", k, address)
			} else {
				return fmt.Errorf("Untrusted client %d should not have been able to connect to %s", k, address)
			}
		}
	}

	return nil
}

func TestMutualAuth(t *testing.T) {
	org1, err := loadOrg(1, 0, false)
	require.NoError(t, err)
	org2, err := loadOrg(2, 0, false)
	require.NoError(t, err)

	tests := []struct {
		name             string
		servers          []server
		trustedClients   []client
		untrustedClients []client
	}{
		{
			name:             "client auth require single org",
			servers:          org1.servers(nil),
			trustedClients:   org1.clients(nil),
			untrustedClients: org2.clients([][]byte{org1.publicKeyPEM}), // 服务端验证客户端的 CA 证书验证不了该客户端的证书
		},
		{
			name:             "client auth require child client org",
			servers:          org1.servers([][]byte{org1.childOrgs[0].publicKeyPEM}),
			trustedClients:   org1.childOrgs[0].clients([][]byte{org1.publicKeyPEM}), // 用根 CA 验证服务端的证书
			untrustedClients: org1.childOrgs[1].clients([][]byte{org1.publicKeyPEM}),
		},
		{
			name:    "client auth require multiple child client orgs",
			servers: org1.servers([][]byte{org1.childOrgs[0].publicKeyPEM, org1.childOrgs[1].publicKeyPEM}),
			trustedClients: append(append([]client{}, org1.childOrgs[0].clients([][]byte{org1.publicKeyPEM})...),
				org1.childOrgs[1].clients([][]byte{org1.publicKeyPEM})...),
			untrustedClients: org2.clients([][]byte{org1.publicKeyPEM}),
		},
		{
			name:             "client auth require different server and client orgs",
			servers:          org1.servers([][]byte{org2.publicKeyPEM}),
			trustedClients:   org2.clients([][]byte{org1.publicKeyPEM}),
			untrustedClients: org1.childOrgs[1].clients([][]byte{org1.publicKeyPEM}), // 服务端的 CA 证书验证不了该客户端的证书
		},
		{
			name:             "client auth require different server and child client orgs",
			servers:          org2.servers([][]byte{org1.childOrgs[0].publicKeyPEM}),
			trustedClients:   org1.childOrgs[0].clients([][]byte{org2.publicKeyPEM}),
			untrustedClients: org2.childOrgs[0].clients([][]byte{org2.publicKeyPEM}), // 服务端的 CA 证书验证不了该客户端的证书
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := runMutualAuth(t, test.servers, test.trustedClients, test.untrustedClients)
			require.NoError(t, err)
		})
	}
}

func TestServerInterceptors(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	defer listener.Close()

	usiCount := uint32(0)
	ssiCount := uint32(0)

	usi1 := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		atomic.AddUint32(&usiCount, 1)
		return handler(ctx, req)
	}
	usi2 := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		atomic.AddUint32(&usiCount, 1)
		return nil, errors.New("error from interceptor")
	}

	ssi := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		atomic.AddUint32(&ssiCount, 100)
		return handler(srv, ss)
	}

	sCfg := comm.ServerConfig{}
	sCfg.UnaryInterceptors = append(sCfg.UnaryInterceptors, usi1)
	sCfg.UnaryInterceptors = append(sCfg.UnaryInterceptors, usi2)
	sCfg.StreamInterceptors = append(sCfg.StreamInterceptors, ssi)

	server, err := comm.NewGRPCServerFromListener(listener, sCfg)
	require.NoError(t, err)
	key, _ := bccsp.GetRandomBytes(32)
	protobuf.RegisterEncryptorDecryptorServer(server.Server(), &edserver{key: key})
	go server.Start()
	defer server.Stop()

	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	client := protobuf.NewEncryptorDecryptorClient(conn)
	res, err := client.Encrypt(context.Background(), &protobuf.Request{Plaintext: []byte("hello")})
	require.Error(t, err)
	require.Nil(t, res)

	require.Equal(t, uint32(2), usiCount)
	require.Equal(t, uint32(0), ssiCount)

	stream, err := client.EncryptStream(context.Background())
	require.NoError(t, err)
	errCh := make(chan error)

	go func() {
		for {
			res, err := stream.Recv()
			if err != nil && err == io.EOF {
				return
			} else if err != nil {
				errCh <- err
			} else {
				fmt.Printf("Stream encrypted: %x\n", res.Ciphertext)
			}
		}
	}()

	err = stream.Send(&protobuf.Request{Plaintext: []byte("hi")})
	require.NoError(t, err)
	stream.CloseSend()

	select {
	case err = <-errCh:
		t.Errorf("Unexpected error: [%s]", err.Error())
	default:

	}

	time.Sleep(time.Millisecond * 20)

	require.Equal(t, uint32(100), atomic.LoadUint32(&ssiCount))
}
