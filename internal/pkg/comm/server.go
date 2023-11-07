package comm

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type GRPCServer struct {
	// 服务端监听的网络地址，格式为 ip:port。
	address string

	listener net.Listener

	server *grpc.Server

	serverCertificate atomic.Value

	lock *sync.Mutex

	tls *tls.Config

	healthServer *health.Server
}

func NewGRPCServer(address string, serverConfig ServerConfig) (*GRPCServer, error) {
	if address == "" {
		return nil, errors.New("missing address parameter")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}

	return NewGRPCServerFromListener(listener, serverConfig)
}

func NewGRPCServerFromListener(listener net.Listener, serverConfig ServerConfig) (*GRPCServer, error) {
	gs := &GRPCServer{
		address:  listener.Addr().String(),
		listener: listener,
		lock:     &sync.Mutex{},
	}

	serverOpts := make([]grpc.ServerOption, 0)

	if serverConfig.SecureOptions.UseTLS {
		// 由于要实现安全传输，所以，需要服务端的证书
		if serverConfig.SecureOptions.PrivateKeyPEM != nil && serverConfig.SecureOptions.PublicKeyPEM != nil {
			cert, err := tls.X509KeyPair(serverConfig.SecureOptions.PublicKeyPEM, serverConfig.SecureOptions.PrivateKeyPEM)
			if err != nil {
				return nil, err
			}
			// 将生成的证书存储一下
			gs.serverCertificate.Store(cert)

			if len(serverConfig.SecureOptions.CipherSuites) == 0 {
				serverConfig.SecureOptions.CipherSuites = DefaultTLSCipherSuites
			}

			getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert := gs.serverCertificate.Load().(tls.Certificate)
				return &cert, nil
			}

			gs.tls = &tls.Config{
				VerifyPeerCertificate:  serverConfig.SecureOptions.VerifyCertificate,
				GetCertificate:         getCert,
				SessionTicketsDisabled: true,
				CipherSuites:           serverConfig.SecureOptions.CipherSuites,
				ClientCAs:              x509.NewCertPool(),
			}

			if serverConfig.SecureOptions.TimeShift > 0 {
				gs.tls.Time = func() time.Time {
					return time.Now().Add((-1) * serverConfig.SecureOptions.TimeShift)
				}
			}

			// 先设置成需要客户端的证书，要不要验证证书的合法性，之后再说
			gs.tls.ClientAuth = tls.RequestClientCert

			if serverConfig.SecureOptions.RequireClientCert {
				gs.tls.ClientAuth = tls.RequireAndVerifyClientCert
				if len(serverConfig.SecureOptions.ClientRootCAs) > 0 {
					for _, clientRootCA := range serverConfig.SecureOptions.ClientRootCAs {
						if err = gs.appendClientRootCAs(clientRootCA); err != nil {
							return nil, err
						}
					}
				}
			}

			gs.tls.MinVersion = tls.VersionTLS12
			gs.tls.MaxVersion = tls.VersionTLS12
			creds := &serverCreddentials{TLSConfig: gs.tls}
			serverOpts = append(serverOpts, grpc.Creds(creds))
		} else {
			return nil, errors.New("the config structure must provide the pem encoded data of private key and public key when use tls")
		}
	}

	maxSendMsgSize := DefaultMaxSendMsgSize
	if serverConfig.MaxSendMsgSize > 0 {
		maxSendMsgSize = serverConfig.MaxSendMsgSize
	}
	maxRecvMsgSize := DefaultMaxRecvMsgSize
	if serverConfig.MaxRecvMsgSize > 0 {
		maxRecvMsgSize = serverConfig.MaxRecvMsgSize
	}

	serverOpts = append(serverOpts, grpc.MaxSendMsgSize(maxSendMsgSize))
	serverOpts = append(serverOpts, grpc.MaxRecvMsgSize(maxRecvMsgSize))

	serverOpts = append(serverOpts, serverConfig.KeepaliveOptions.ToGRPCServerOptions()...)

	if serverConfig.ConnectionTimeout <= 0 {
		serverConfig.ConnectionTimeout = DefaultConnectionTimeout
	}
	serverOpts = append(serverOpts, grpc.ConnectionTimeout(serverConfig.ConnectionTimeout))

	if len(serverConfig.StreamInterceptors) > 0 {
		serverOpts = append(serverOpts, grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(serverConfig.StreamInterceptors...)))
	}

	if len(serverConfig.UnaryInterceptors) > 0 {
		serverOpts = append(serverOpts, grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(serverConfig.UnaryInterceptors...)))
	}

	if serverConfig.ServerStatsHandler != nil {
		serverOpts = append(serverOpts, grpc.StatsHandler(serverConfig.ServerStatsHandler))
	}

	gs.server = grpc.NewServer(serverOpts...)

	if serverConfig.HealthCheckEnabled {
		gs.healthServer = health.NewServer()
		healthpb.RegisterHealthServer(gs.server, gs.healthServer)
	}

	return gs, nil
}

func (gs *GRPCServer) SetServerCertificate(cert tls.Certificate) {
	gs.serverCertificate.Store(cert)
}

func (gs *GRPCServer) Address() string {
	return gs.address
}

func (gs *GRPCServer) Listener() net.Listener {
	return gs.listener
}

func (gs *GRPCServer) Server() *grpc.Server {
	return gs.server
}

// ServerCertificate 返回服务端的身份证书。
func (gs *GRPCServer) ServerCertificate() tls.Certificate {
	return gs.serverCertificate.Load().(tls.Certificate)
}

// TLSEnabled 只是返回 GRPCServer 的 TLS 配置是否不为空。
func (gs *GRPCServer) TLSEnabled() bool {
	return gs.tls != nil
}

// MutualTLSRequired 是否需要验证客户端身份。
func (gs *GRPCServer) MutualTLSRequired() bool {
	return gs.TLSEnabled() && gs.tls.ClientAuth == tls.RequireAndVerifyClientCert
}

func (gs *GRPCServer) Start() error {
	if gs.healthServer != nil {
		for name := range gs.server.GetServiceInfo() {
			gs.healthServer.SetServingStatus(name, healthpb.HealthCheckResponse_SERVING)
		}

		gs.healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	}

	return gs.server.Serve(gs.listener)
}

func (gs *GRPCServer) Stop() {
	gs.server.Stop()
}

// SetClientRootCAs 设置验证客户端身份的 CA 证书。
func (gs *GRPCServer) SetClientRootCAs(clientRoots [][]byte) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()

	certPool := x509.NewCertPool()
	for _, clientRoot := range clientRoots {
		if !certPool.AppendCertsFromPEM(clientRoot) {
			return errors.New("failed to set client root certificate(s)")
		}
	}

	gs.tls.ClientCAs = certPool
	return nil
}

func (gs *GRPCServer) appendClientRootCAs(clientRoots []byte) error {
	certs, err := pemToX509Certs(clientRoots)
	if err != nil {
		return fmt.Errorf("failed to append client root certificate: [%s]", err.Error())
	}

	if len(certs) < 1 {
		return errors.New("no client root certificate found")
	}

	for _, cert := range certs {
		gs.tls.ClientCAs.AddCert(cert)
	}

	return nil
}

func pemToX509Certs(pemCerts []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}

	return certs, nil
}
