package comm

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	"google.golang.org/grpc/credentials"
)

var (
	ErrClientHandshakeNotImplemented = errors.New("pkg/comm: client handshake are not implemented with serverCreds")
	ErrServerHandshakeNotImplemented = errors.New("pkg/comm: server handshake are not implemented with clientCreds")
	ErrOverrideHostnameNotSupported  = errors.New("pkg/comm: OverrideServerName is not supported")

	tlsClientLogger = hlogging.MustGetLogger("comm.tls.client")
	tlsServerLogger = hlogging.MustGetLogger("comm.tls.server")
)

/*** 🐋 ***/

// client

// clientCredentials 客户凭证
type clientCredentials struct {
	TLSConfig *tls.Config // 配置信息一旦确定，则一般情况下不可更改。
}

func (cc *clientCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	l := tlsClientLogger.With("remote address", rawConn.RemoteAddr().String())
	creds := credentials.NewTLS(cc.TLSConfig.Clone()) // 实际上只是把 *tls.Config 包装了一下，包装成了 &tlsCreds{*tls.Config}
	start := time.Now()
	conn, auth, err := creds.ClientHandshake(ctx, authority, rawConn)
	if err != nil {
		l.Errorf("Client TLS handshake failed after %s with error: [%s].", time.Since(start), err.Error())
		return nil, nil, err
	} else {
		l.Debugf("Client TLS handshake completed in %s.", time.Since(start))
	}

	return conn, auth, nil
}

func (cc *clientCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ErrServerHandshakeNotImplemented
}

func (cc *clientCredentials) Info() credentials.ProtocolInfo {
	return credentials.NewTLS(cc.TLSConfig.Clone()).Info()
}

func (cc *clientCredentials) Clone() credentials.TransportCredentials {
	return credentials.NewTLS(cc.TLSConfig.Clone())
}

// OverrideServerName 覆盖 ServerName，ServerName 用于验证返回证书上的主机名。
func (cc *clientCredentials) OverrideServerName(name string) error {
	cc.TLSConfig.ServerName = name
	return nil
}

/*** 🐋 ***/

// server

type serverCreddentials struct {
	TLSConfig *tls.Config
}

func (sc *serverCreddentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ErrClientHandshakeNotImplemented
}

func (sc *serverCreddentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn := tls.Server(rawConn, sc.TLSConfig.Clone())
	l := tlsServerLogger.With("remote address", conn.RemoteAddr().String())
	start := time.Now()
	if err := conn.Handshake(); err != nil {
		l.Errorf("Server TLS handshake failed in %s with error: [%s].", time.Since(start), err.Error())
		return nil, nil, err
	} else {
		l.Debugf("Server TLS handshake completed in %s.", time.Since(start))
	}

	return conn, credentials.TLSInfo{State: conn.ConnectionState()}, nil
}

func (sc *serverCreddentials) Info() credentials.ProtocolInfo {
	return credentials.NewTLS(sc.TLSConfig.Clone()).Info()
}

func (sc *serverCreddentials) Clone() credentials.TransportCredentials {
	return &serverCreddentials{TLSConfig: sc.TLSConfig.Clone()}
}

func (sc *serverCreddentials) OverrideServerName(name string) error {
	return ErrOverrideHostnameNotSupported
}
