package test

import "crypto/x509"

type ServerConfig struct {
	VerifyCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate)
}