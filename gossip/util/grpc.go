package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"strconv"
	"time"

	"github.com/11090815/hyperchain/common/crypto/tlsgen"
	"github.com/11090815/hyperchain/gossip/api"
	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/internal/pkg/comm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var ca = createCAOrPanic()

func createCAOrPanic() *tlsgen.CA {
	ca, err := tlsgen.NewCA()
	if err != nil {
		panic(err)
	}
	return ca
}

func CreateGRPCLayer() (port int, gRPCServer *comm.GRPCServer, certs *common.TLSCertificates, secureDialOpts api.PeerSecureDialOpts, dialOpts []grpc.DialOption) {
	serverKeyPair, err := ca.NewServerCertKeyPair("127.0.0.1")
	if err != nil {
		panic(err)
	}
	clientKeyPair, err := ca.NewClientCertKeyPair()
	if err != nil {
		panic(err)
	}

	tlsServerCert, err := tls.X509KeyPair(serverKeyPair.PublicKeyPEM(), serverKeyPair.PrivateKeyPEM())
	if err != nil {
		panic(err)
	}
	tlsClientCert, err := tls.X509KeyPair(clientKeyPair.PublicKeyPEM(), clientKeyPair.PrivateKeyPEM())
	if err != nil {
		panic(err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{tlsClientCert},
		ClientAuth:   tls.RequestClientCert,
		RootCAs:      x509.NewCertPool(),
	}
	tlsConf.RootCAs.AppendCertsFromPEM(ca.PublicKeyPEM())
	transportCredentials := credentials.NewTLS(tlsConf)

	dialOpts = append(dialOpts, grpc.WithTransportCredentials(transportCredentials))

	secureDialOpts = func() []grpc.DialOption {
		return dialOpts
	}

	certs = &common.TLSCertificates{}
	certs.TLSClientCert.Store(&tlsClientCert)
	certs.TLSServerCert.Store(&tlsServerCert)

	srvConfig := comm.ServerConfig{
		ConnectionTimeout: time.Second,
		SecureOptions: comm.SecureOptions{
			PrivateKeyPEM: serverKeyPair.PrivateKeyPEM(),
			PublicKeyPEM:  serverKeyPair.PublicKeyPEM(),
			UseTLS:        true,
			// RequireClientCert: true,
			// ClientRootCAs:     [][]byte{ca.PublicKeyPEM()},
		},
	}

	gRPCServer, err = comm.NewGRPCServer("127.0.0.1:", srvConfig)
	if err != nil {
		panic(err)
	}

	_, portStr, err := net.SplitHostPort(gRPCServer.Address())
	if err != nil {
		panic(err)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		panic(err)
	}

	return port, gRPCServer, certs, secureDialOpts, dialOpts
}

func GenerateTLSCertificatesOrPanic() tls.Certificate {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		SerialNumber: sn,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	rawBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rawBytes})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER})
	cert, err := tls.X509KeyPair(certPEM, privateKeyPEM)
	if err != nil {
		panic(err)
	}
	return cert
	// clientCert, _ := ca.NewClientCertKeyPair()
	// cert, _ := tls.X509KeyPair(clientCert.PublicKeyPEM(), clientCert.PrivateKeyPEM())
	// return cert
}
