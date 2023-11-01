package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

const (
	DefaultMaxRecvMsgSize = 100 * 1024 * 1024
	DefaultMaxSendMsgSize = 100 * 1024 * 1024
)

var (
	DefaultKeepaliveOptions = KeepaliveOptions{
		ClientPingServerInterval:    time.Minute,
		ClientPingServerTimeout:     20 * time.Second,
		ServerPingClientInterval:    2 * time.Hour,
		ServerPingClientTimeout:     20 * time.Second,
		ClientPingServerMinInterval: time.Minute,
	}
)

type ServerConfig struct {
	ConnectionTimeout  time.Duration
	SecureOptions      SecureOptions
	KeepaliveOptions   KeepaliveOptions
	StreamInterceptors []grpc.StreamServerInterceptor
	UnaryInterceptors  []grpc.UnaryServerInterceptor
	Logger             *hlogging.HyperchainLogger
	HealthCheckEnabled bool
	ServerStatsHandler *ServerStatsHandler
	MaxRecvMsgSize     int
	MaxSendMsgSize     int
}

/* 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 */

type ClientConfig struct {
	// 创建 TLS 连接时用到的选项
	SecureOptions SecureOptions

	// 保持连接活跃的选项，包括：
	//	Client：
	//		- 客户端向服务端发送 ping 的时间间隔
	//		- 客户端等待服务端回应 ping 的超时时间
	//		- 允许客户端向服务端发送 ping 的最短时间间隔
	//	Server：
	//		- 服务端向客户端发送 ping 的时间间隔
	//		- 服务端等待客户端回应 ping 的超时时间
	KeepaliveOptions KeepaliveOptions

	// 客户端与服务端建立连接的超时等待时间
	DialTimeout time.Duration

	// 以非阻塞的形式创建连接
	AsyncConnect bool

	// 客户端允许接收的消息最大大小
	MaxRecvMsgSize int

	// 客户端允许发送的消息最大大小
	MaxSendMsgSize int
}

func (cc ClientConfig) GetGRPCDialOptions() ([]grpc.DialOption, error) {
	var opts = make([]grpc.DialOption, 0)
	opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                cc.KeepaliveOptions.ClientPingServerInterval, // 客户端 ping 服务端的时间间隔
		Timeout:             cc.KeepaliveOptions.ClientPingServerTimeout,  // 客户端等待服务端回应 ping 的超时时间
		PermitWithoutStream: true,
	}))

	if !cc.AsyncConnect {
		opts = append(opts,
			grpc.WithBlock(),
			grpc.FailOnNonTempDialError(true), // 如果为 true，且拨号器返回非暂时性错误，gRPC 将无法连接到网络地址，那么则不会尝试重新连接。
		)
	}

	maxRecvMsgSize := DefaultMaxRecvMsgSize
	if cc.MaxRecvMsgSize != 0 {
		maxRecvMsgSize = cc.MaxRecvMsgSize
	}

	maxSendMsgSize := DefaultMaxSendMsgSize
	if cc.MaxSendMsgSize != 0 {
		maxSendMsgSize = cc.MaxSendMsgSize
	}

	opts = append(opts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxRecvMsgSize), grpc.MaxCallSendMsgSize(maxSendMsgSize)))

	tlsCfg, err := cc.SecureOptions.ToTLSConfig()
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		creds := &clientCredentials{TLSConfig: tlsCfg}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	return opts, nil
}

func (cc ClientConfig) Dial(address string) (*grpc.ClientConn, error) {
	opts, err := cc.GetGRPCDialOptions()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cc.DialTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, address, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed creating new grpc connection: [%s]", err.Error())
	}

	return conn, nil
}

/* 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 🐋 */

type SecureOptions struct {
	// 建立握手连接时，验证客户端或服务端的证书。
	VerifyCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// ASN.1 DER PEM 编码的 x509 证书。
	PublicKeyPEM []byte

	// ASN.1 DER PEM 编码的密钥，用于 TLS 通信。
	PrivateKeyPEM []byte

	// ASN.1 DER PEM 编码的证书，客户端用它来验证服务端的身份。
	ServerRootCAs [][]byte

	// ASN.1 DER PEM 编码的证书，服务端用它来验证客户端的身份。
	ClientRootCAs [][]byte

	// 是否使用 TLS 用于通信。
	UseTLS bool

	// 再进行身份验证的时候，是否需要客户端提供证书。
	RequireClientCert bool

	// TLS 支持的密码套件。
	CipherSuites []uint16

	// TODO 为什么要有时间偏移？
	TimeShift time.Duration

	// 用于验证返回证书上的主机名，除非给出 InsecureSkipVerify。除非是 IP 地址，否则它也会被包含在客户端的握手过程中，以支持虚拟主机。
	ServerNameOverride string
}

func (so SecureOptions) ToTLSConfig() (*tls.Config, error) {
	if !so.UseTLS {
		// 不使用 TLS 进行通信
		return nil, nil
	}

	cfg := &tls.Config{
		MinVersion:            tls.VersionTLS12,
		ServerName:            so.ServerNameOverride,
		VerifyPeerCertificate: so.VerifyCertificate,
	}

	if len(so.ServerRootCAs) > 0 {
		cfg.RootCAs = x509.NewCertPool()
		for _, cert := range so.ServerRootCAs {
			if !cfg.RootCAs.AppendCertsFromPEM(cert) {
				return nil, errors.New("failed adding root certificate")
			}
		}
	}

	if so.RequireClientCert {
		cert, err := so.ClientCertificate()
		if err != nil {
			return nil, fmt.Errorf("require the certificate of the client, but %s", err.Error())
		}
		cfg.Certificates = append(cfg.Certificates, cert)
	}

	if so.TimeShift > 0 {
		cfg.Time = func() time.Time {
			return time.Now().Add((-1) * so.TimeShift)
		}
	}

	return cfg, nil
}

// ClientCertificate 根据 PEM 编码的 x509 公钥和私钥，生成一个 TLS 证书。
func (so *SecureOptions) ClientCertificate() (tls.Certificate, error) {
	if so.PublicKeyPEM == nil || so.PrivateKeyPEM == nil {
		return tls.Certificate{}, errors.New("public/private key pair of a pair of PEM encoded data should not be nil")
	}

	cert, err := tls.X509KeyPair(so.PublicKeyPEM, so.PrivateKeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed creating TLS certificate: [%s]", err.Error())
	}

	return cert, nil
}

/*** 🐋 ***/

type KeepaliveOptions struct {
	// ClientPingServerInterval 客户端在看不到服务端的活动时，为了检查服务端的状态，ping 服务端的时间间隔。
	ClientPingServerInterval time.Duration

	// ClientPingServerTimeout 客户端 ping 服务端后，等待的超时时间，如果在该时间段内没有收到服务端的回复，则会关闭连接。
	ClientPingServerTimeout time.Duration

	// ServerPingClientInterval 服务端在看不到客户端的活动时，为了检查客户端的状态，ping 客户端的时间间隔。
	ServerPingClientInterval time.Duration

	// ServerPingClientTimeout 服务端 ping 客户端后，等待的超时时间，如果在该时间段内没有收到客户端的回复，则会关闭连接。
	ServerPingClientTimeout time.Duration

	// ClientPingServerMinInterval 允许客户端 ping 服务端的最短时间间隔，时间间隔太短的话，客户端会 ping 的过于频繁，那么服务端可以关闭与客户端的连接。
	ClientPingServerMinInterval time.Duration
}

// ToGRPCServerOptions 导出 grpc 连接中服务端的选项：
//  1. 服务端 ping 客户端的时间间隔：ServerPingClientInterval
//  2. 服务端 ping 客户端后等待的超时时间：ServerPingClientTimeout
//  3. 服务端允许客户端 ping 自己的最短时间间隔：ClientPingServerMinInterval
//  4. 当 grpc 的连接上没有活动流时，服务端依然允许客户端 ping 自己
func (ko *KeepaliveOptions) ToGRPCServerOptions() []grpc.ServerOption {
	var opts = make([]grpc.ServerOption, 0)

	parameters := keepalive.ServerParameters{
		Time:    ko.ServerPingClientInterval,
		Timeout: ko.ServerPingClientTimeout,
	}

	policies := keepalive.EnforcementPolicy{
		MinTime:             ko.ClientPingServerMinInterval,
		PermitWithoutStream: true, // 如果为 "true"，即使没有活动流，服务器也允许服务端向其发送 ping。如果为 "false"，客户端在没有活动流时发送 ping，服务器将发送 GOAWAY 并关闭连接。
	}

	opts = append(opts, grpc.KeepaliveParams(parameters), grpc.KeepaliveEnforcementPolicy(policies))

	return opts
}

// ToGRPCDialOptions 导出 grpc 连接中，客户端给服务端拨号时的选项：
//  1. 客户端 ping 服务端的时间间隔：ClientPingServerInterval
//  2. 客户端 ping 服务端后等待的超时时间：ClientPingServerTimeout
//  3. 当 grpc 的连接上没有活动流时，客户端依然会给服务端发送 ping
func (ko *KeepaliveOptions) ToGRPCDialOptions() []grpc.DialOption {
	var opts = make([]grpc.DialOption, 0)

	parameters := keepalive.ClientParameters{
		Time:                ko.ClientPingServerInterval,
		Timeout:             ko.ClientPingServerTimeout,
		PermitWithoutStream: true, // 如果为 "true"，即使没有活动流，客户端也会发送 ping 给服务端。如果为假，当没有活动流时，不会发送 ping。
	}

	opts = append(opts, grpc.WithKeepaliveParams(parameters))

	return opts
}
