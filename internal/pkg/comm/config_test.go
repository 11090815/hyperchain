package comm

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/11090815/hyperchain/common/crypto/tlsgen"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

func TestServerKeepaliveOptions(t *testing.T) {
	parameters := keepalive.ServerParameters{
		Time:    DefaultKeepaliveOptions.ServerPingClientInterval,
		Timeout: DefaultKeepaliveOptions.ServerPingClientTimeout,
	}

	policies := keepalive.EnforcementPolicy{
		MinTime:             DefaultKeepaliveOptions.ClientPingServerMinInterval,
		PermitWithoutStream: true,
	}

	expectedOpts := []grpc.ServerOption{
		grpc.KeepaliveParams(parameters),
		grpc.KeepaliveEnforcementPolicy(policies),
	}

	opts := DefaultKeepaliveOptions.ToGRPCServerOptions()

	require.Len(t, opts, len(expectedOpts))

	for i := range opts {
		require.IsType(t, expectedOpts[i], opts[i])
	}
}

func TestClientKeepaliveOptions(t *testing.T) {
	parameters := keepalive.ClientParameters{
		Time:                DefaultKeepaliveOptions.ClientPingServerInterval,
		Timeout:             DefaultKeepaliveOptions.ClientPingServerTimeout,
		PermitWithoutStream: true,
	}
	expectedOpts := []grpc.DialOption{grpc.WithKeepaliveParams(parameters)}
	opts := DefaultKeepaliveOptions.ToGRPCDialOptions()

	require.Len(t, opts, len(expectedOpts))
	for i := range opts {
		require.IsType(t, expectedOpts[i], opts[i])
	}
}

func TestClientConfigClone(t *testing.T) {
	origin := ClientConfig{
		KeepaliveOptions: KeepaliveOptions{
			ClientPingServerInterval: time.Second,
		},
		SecureOptions: SecureOptions{
			PrivateKeyPEM: []byte{1, 2, 3},
		},
		DialTimeout:  time.Second,
		AsyncConnect: true,
	}

	clone := origin

	require.Equal(t, origin, clone)

	origin.AsyncConnect = false
	origin.KeepaliveOptions.ServerPingClientInterval = time.Second
	origin.KeepaliveOptions.ClientPingServerInterval = time.Hour
	origin.SecureOptions.PublicKeyPEM = []byte{1, 2, 3}
	origin.SecureOptions.PrivateKeyPEM = []byte{4, 5, 6}
	origin.DialTimeout = time.Second * 2

	clone.SecureOptions.UseTLS = true
	clone.KeepaliveOptions.ClientPingServerMinInterval = time.Hour

	expectedOriginState := ClientConfig{
		KeepaliveOptions: KeepaliveOptions{
			ClientPingServerInterval: time.Hour,
			ServerPingClientInterval: time.Second,
		},
		SecureOptions: SecureOptions{
			PrivateKeyPEM: []byte{4, 5, 6},
			PublicKeyPEM:  []byte{1, 2, 3},
		},
		DialTimeout: time.Second * 2,
	}

	expectedCloneState := ClientConfig{
		KeepaliveOptions: KeepaliveOptions{
			ClientPingServerInterval:    time.Second,
			ClientPingServerMinInterval: time.Hour,
		},
		SecureOptions: SecureOptions{
			PrivateKeyPEM: []byte{1, 2, 3},
			UseTLS:        true,
		},
		DialTimeout:  time.Second,
		AsyncConnect: true,
	}

	require.Equal(t, expectedCloneState, clone)
	require.Equal(t, expectedOriginState, origin)
}

func TestSecureOptionsTLSConfig(t *testing.T) {
	ca1, err := tlsgen.NewCA()
	require.NoError(t, err)

	ca2, err := tlsgen.NewCA()
	require.NoError(t, err)

	ckp, err := ca1.NewClientCertKeyPair()
	require.NoError(t, err)

	clientCert, err := tls.X509KeyPair(ckp.PublicKeyPEM(), ckp.PrivateKeyPEM())
	require.NoError(t, err)

	newCertPool := func(cas ...*tlsgen.CA) *x509.CertPool {
		pool := x509.NewCertPool()
		for _, ca := range cas {
			ok := pool.AppendCertsFromPEM(ca.CertBytes())
			require.True(t, ok)
		}
		return pool
	}

	tests := []struct {
		desc        string
		so          SecureOptions
		tc          *tls.Config
		expectedErr string
	}{
		{desc: "TLSDisabled"},
		{desc: "TLSDisabled", so: SecureOptions{UseTLS: true}, tc: &tls.Config{MinVersion: tls.VersionTLS12}},
		{
			desc: "ServerNameOverride",
			so:   SecureOptions{UseTLS: true, ServerNameOverride: "bob"},
			tc:   &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "bob"},
		},
		{
			desc: "WithServerRootCAs",
			so:   SecureOptions{UseTLS: true, ServerRootCAs: [][]byte{ca1.CertBytes(), ca2.CertBytes()}},
			tc:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: newCertPool(ca1, ca2)},
		},
		{
			desc: "BadServerRootCertificate",
			so: SecureOptions{
				UseTLS: true,
				ServerRootCAs: [][]byte{
					[]byte("-----BEGIN CERTIFICATE-----\nYm9ndXM=\n-----END CERTIFICATE-----"),
				},
			},
			expectedErr: "failed adding root certificate",
		},
		{
			desc: "WithRequiredClientKeyPair",
			so:   SecureOptions{UseTLS: true, RequireClientCert: true, PrivateKeyPEM: ckp.PrivateKeyPEM(), PublicKeyPEM: ckp.PublicKeyPEM()},
			tc:   &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{clientCert}},
		},
		{
			desc:        "MissingClientKey",
			so:          SecureOptions{UseTLS: true, RequireClientCert: true, PublicKeyPEM: ckp.PublicKeyPEM()},
			expectedErr: "public/private key pair of a pair of PEM encoded data should not be nil",
		},
		{
			desc:        "MissingClientCert",
			so:          SecureOptions{UseTLS: true, RequireClientCert: true, PrivateKeyPEM: ckp.PrivateKeyPEM()},
			expectedErr: "public/private key pair of a pair of PEM encoded data should not be nil",
		},
		{
			desc: "WithTimeShift",
			so:   SecureOptions{UseTLS: true, TimeShift: 2 * time.Hour},
			tc:   &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			tc, err := test.so.ToTLSConfig()
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
				return
			}
			require.NoError(t, err)

			if len(test.so.ServerRootCAs) > 0 {
				require.NotNil(t, tc.RootCAs)
				require.True(t, test.tc.RootCAs.Equal(tc.RootCAs))
				test.tc.RootCAs, tc.RootCAs = nil, nil
			}

			if test.so.TimeShift != 0 {
				require.NotNil(t, tc.Time)
				require.WithinDuration(t, time.Now().Add((-1)*test.so.TimeShift), tc.Time(), 10*time.Second)
				tc.Time = nil
			}

			require.Equal(t, test.tc, tc)
		})
	}
}

type Key struct {
	content []byte
}

func (k *Key) GetContent() []byte {
	return k.content
}

func TestReturnAddressOfSliceInStruct(t *testing.T) {
	k := &Key{content: []byte{1, 2, 3}}

	c := k.GetContent()

	addressOfOrigin := fmt.Sprintf("%p", k.content)
	addressOfReturned := fmt.Sprintf("%p", c)

	require.Equal(t, addressOfOrigin, addressOfReturned)

	c[0] = byte(2)

	addressOfOrigin = fmt.Sprintf("%p", k.content)
	addressOfReturned = fmt.Sprintf("%p", c)

	require.Equal(t, addressOfOrigin, addressOfReturned)

	require.Equal(t, c, k.content)
	require.Equal(t, c, k.GetContent())
}

func TestClientConfigDialOptions_GoodConfig(t *testing.T) {
	
}
