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
	"testing"
	"time"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/internal/pkg/comm"
	"github.com/11090815/hyperchain/internal/pkg/comm/testdata/protobuf"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const timeout = time.Second

type edserver struct {
	key []byte
}

func (s *edserver) Encrypt(ctx context.Context, req *protobuf.Request) (*protobuf.Reply, error) {
	var err error
	var reply protobuf.Reply

	if len(req.Plaintext) == 0 {
		return nil, errors.New("encrypt: plaintext should not be empty")
	}

	reply.Ciphertext, err = bccsp.AESCBCPKCS7Encrypt(s.key, req.Plaintext)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

func (s *edserver) Decrypt(ctx context.Context, req *protobuf.Request) (*protobuf.Reply, error) {
	var err error
	var reply protobuf.Reply

	if len(req.Ciphertext) == 0 {
		return nil, errors.New("decrypt: ciphertext should not be empty")
	}

	reply.Plaintext, err = bccsp.AESCBCPKCS7Decrypt(s.key, req.Ciphertext)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

func (s *edserver) EncryptStream(stream protobuf.EncryptorDecryptor_EncryptStreamServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		} else {
			if len(req.Plaintext) == 0 {
				return errors.New("encrypt: plaintext should not be empty")
			}
			var err error
			var reply protobuf.Reply
			if reply.Ciphertext, err = bccsp.AESCBCPKCS7Encrypt(s.key, req.Plaintext); err != nil {
				return err
			}
			if err = stream.Send(&reply); err != nil {
				return err
			}
		}
	}
}

func (s *edserver) DecryptStream(stream protobuf.EncryptorDecryptor_DecryptStreamServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		} else {
			if len(req.Ciphertext) == 0 {
				return errors.New("decrypt: ciphertext should not be empty")
			}
			var err error
			var reply protobuf.Reply
			if reply.Plaintext, err = bccsp.AESCBCPKCS7Decrypt(s.key, req.Ciphertext); err != nil {
				return err
			}
			if err = stream.Send(&reply); err != nil {
				return err
			}
		}
	}
}

func TestClientConfigDial(t *testing.T) {
	certs := comm.LoadTestCerts(t)

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)
	badAddress := listener.Addr().String()
	defer listener.Close()

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(certs.CAPEM)
	require.True(t, ok)

	tests := []struct {
		name          string
		clientAddress string
		clientConfig  comm.ClientConfig
		serverConfig  *tls.Config
		success       bool
		errorMsg      string
	}{
		{
			name: "cient / server same port",
			clientConfig: comm.ClientConfig{
				DialTimeout: timeout,
			},
			success: true,
		},
		{
			name:          "client / server wrong port but with asynchronous should succeed",
			clientAddress: badAddress,
			clientConfig: comm.ClientConfig{
				AsyncConnect: true,
				DialTimeout:  timeout * 5,
			},
			success: true,
		},
		{
			name:          "client / server wrong port",
			clientAddress: badAddress,
			clientConfig: comm.ClientConfig{
				DialTimeout: timeout,
			},
			success:  false,
			errorMsg: "context deadline exceeded",
		},
		{
			name: "client TLS / server no TLS",
			clientConfig: comm.ClientConfig{
				SecureOptions: comm.SecureOptions{
					UseTLS: true,
				},
				DialTimeout: timeout,
			},
			success:  false,
			errorMsg: "context deadline exceeded",
		},
		{
			name: "client TLS / server TLS match",
			clientConfig: comm.ClientConfig{
				SecureOptions: comm.SecureOptions{
					UseTLS:        true,
					ServerRootCAs: [][]byte{certs.CAPEM},
				},
				DialTimeout: timeout,
			},
			serverConfig: &tls.Config{
				Certificates: []tls.Certificate{certs.ServerCert},
			},
			success: true,
		},
		{
			name: "client TLS / server TLS no server roots",
			clientConfig: comm.ClientConfig{
				SecureOptions: comm.SecureOptions{
					UseTLS:        true,
					ServerRootCAs: [][]byte{},
				},
				DialTimeout: timeout,
			},
			serverConfig: &tls.Config{
				Certificates: []tls.Certificate{certs.ServerCert},
			},
			success:  false,
			errorMsg: "context deadline exceeded",
		},
		{
			name: "client TLS /server TLS missing client cert",
			clientConfig: comm.ClientConfig{
				SecureOptions: comm.SecureOptions{
					PublicKeyPEM:  certs.CertPEM,
					PrivateKeyPEM: certs.KeyPEM,
					UseTLS:        true,
					ServerRootCAs: [][]byte{certs.CAPEM},
				},
				DialTimeout: timeout,
			},
			serverConfig: &tls.Config{
				Certificates: []tls.Certificate{certs.ServerCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				MinVersion:   tls.VersionTLS12,
			},
			success:  false,
			errorMsg: "context deadline exceeded",
		},
		{
			name: "client TLS / server TLS client cert",
			clientConfig: comm.ClientConfig{
				SecureOptions: comm.SecureOptions{
					UseTLS: true,
					PublicKeyPEM: certs.CertPEM,
					PrivateKeyPEM: certs.KeyPEM,
					ServerRootCAs: [][]byte{certs.CAPEM},
					RequireClientCert: true,
				},
				DialTimeout: timeout,
			},
			serverConfig: &tls.Config{
				Certificates: []tls.Certificate{certs.ServerCert},
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs: certPool,
			},
			success: true,
		},
		{
			name: "server TLS pining success",
			clientConfig: comm.ClientConfig{
				SecureOptions: comm.SecureOptions{
					VerifyCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
						if bytes.Equal(rawCerts[0], certs.ServerCert.Certificate[0]) {
							return nil
						}
						panic("mismatched certificate")
					},
					PublicKeyPEM: certs.CertPEM,
					PrivateKeyPEM: certs.KeyPEM,
					UseTLS: true,
					RequireClientCert: true,
					ServerRootCAs: [][]byte{certs.CAPEM},
				},
				DialTimeout: timeout,
			},
			serverConfig: &tls.Config{
				Certificates: []tls.Certificate{certs.ServerCert},
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs: certPool,
			},
			success: true,
		},
		{
			name: "server TLS pining success",
			clientConfig: comm.ClientConfig{
				SecureOptions: comm.SecureOptions{
					VerifyCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
						return errors.New("always failure")
					},
					PublicKeyPEM: certs.CertPEM,
					PrivateKeyPEM: certs.KeyPEM,
					UseTLS: true,
					RequireClientCert: true,
					ServerRootCAs: [][]byte{certs.CAPEM},
				},
				DialTimeout: timeout,
			},
			serverConfig: &tls.Config{
				Certificates: []tls.Certificate{certs.ServerCert},
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs: certPool,
			},
			success: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()

			serverOpts := []grpc.ServerOption{}
			if test.serverConfig != nil {
				serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(test.serverConfig)))
			}
			s := grpc.NewServer(serverOpts...)
			defer s.Stop()
			go s.Serve(listener)
			address := listener.Addr().String()
			if test.clientAddress != "" {
				address = test.clientAddress
			}
			conn, err := test.clientConfig.Dial(address)
			if test.success {
				require.NoError(t, err)
				require.NotNil(t, conn)

			} else {
				// t.Log(err)
				require.ErrorContains(t, err, test.errorMsg)
			}
		})
	}
}

func TestSetMessageSize(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	
	s, err := comm.NewGRPCServerFromListener(listener, comm.ServerConfig{})
	require.NoError(t, err)

	key, err := bccsp.GetRandomBytes(32)
	require.NoError(t, err)
	protobuf.RegisterEncryptorDecryptorServer(s.Server(), &edserver{key: key})

	defer s.Stop()
	go s.Start()

	tests := []struct{
		name string
		maxRecvSize int
		maxSendSize int
		failRecv bool
		failSend bool
	}{
		{
			name: "defaults should pass",
			failRecv: false,
			failSend: false,
		},
		{
			name: "non-defaults should pass",
			failRecv: false,
			failSend: false,
			maxRecvSize: 40,
			maxSendSize: 40,
		},
		{
			name: "non-defaults should pass",
			failRecv: true,
			failSend: false,
			maxRecvSize: 20,
			maxSendSize: 40,
		},
		{
			name: "non-defaults should pass",
			failSend: true,
			maxSendSize: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := comm.ClientConfig{
				DialTimeout: timeout,
				MaxRecvMsgSize: test.maxRecvSize,
				MaxSendMsgSize: test.maxSendSize,
			}
			conn, err := config.Dial(address)
			require.NoError(t, err)
			defer conn.Close()

			client := protobuf.NewEncryptorDecryptorClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			req := &protobuf.Request{Plaintext: []byte{1, 2, 3, 4, 5}}
			res, err := client.Encrypt(ctx, req)
			if !test.failRecv && !test.failSend {
				require.NoError(t, err)
				fmt.Printf("Encrypted result: %x\n", res.Ciphertext)
			}
			if test.failSend {
				t.Log(err)
				require.ErrorContains(t, err, "trying to send message larger than max")
			}
			if test.failRecv {
				t.Log(err)
				require.ErrorContains(t, err, "received message larger than max")
			}
		})
	}
}
