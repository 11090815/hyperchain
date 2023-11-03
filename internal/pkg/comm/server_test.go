package comm_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/11090815/hyperchain/internal/pkg/comm"
	"github.com/stretchr/testify/require"
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

func (o *org) rootCertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(o.publicKeyPEM)
	return pool
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
					ServerRootCAs: serverRootCAs,
					UseTLS:        true,
					PublicKeyPEM:  cc.publicKeyPEM,
					PrivateKeyPEM: cc.privateKeyPEM,
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
	_, err := comm.NewGRPCServer("", comm.ServerConfig{})
	require.ErrorContains(t, err, "missing address")

	
}
