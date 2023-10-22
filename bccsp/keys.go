package bccsp

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func privateKeyToPEM(privateKey interface{}) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("invalid key: [it shouldn't be nil]")
	}

	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if key == nil {
			return nil, errors.New("invalid ecdsa private key: [it shouldn't be nil]")
		}

		privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("error marshaling ecdsa key to asn1: [%s]", err)
		}

		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: privateKeyBytes,
			},
		), nil

	default:
		return nil, errors.New("invalid key type: [it must be *ecdsa.PrivateKey]")
	}
}

func pemToPrivateKey(raw []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM: [the content is empty]")
	}

	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("failed decoding PEM to private key")
	}
	_ = rest

	return derToPrivateKey(block.Bytes)
}

func pemToAES(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM: [the content is empty]")
	}

	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("failed decoding PEM to aes key")
	}
	_ = rest

	return block.Bytes, nil
}

func aesToPEM(key []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "AES PRIVATE KEY", Bytes: key})
}

func publicKeyToPEM(publicKey interface{}) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("invalid public key: [it shouldn't be nil]")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("invalid ecdsa public key: [it shouldn't be nil]")
		}
		encoded, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed marshaing ecdsa public key: [%s]", err.Error())
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), nil
	default:
		return nil, errors.New("invalid key type: [it must be *ecdsa.PublicKey]")
	}
}

func pemToPublicKey(raw []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM: [the content is empty]")
	}

	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("failed decoding PEM to public key")
	}
	_ = rest

	return derToPublicKey(block.Bytes)
}

// derToPublicKey 大概率返回 *ecdsa.PublicKey。
func derToPublicKey(raw []byte) (pub interface{}, err error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("invalid DER: [the content is empty]")
	}

	return x509.ParsePKIXPublicKey(raw)
}

// derToPrivateKey 大概率返回 *ecdsa.PrivateKey。
func derToPrivateKey(raw []byte) (key interface{}, err error) {
	if key, err = x509.ParsePKCS1PrivateKey(raw); err == nil {
		return key, nil
	}

	if key, err = x509.ParsePKCS8PrivateKey(raw); err == nil {
		switch key.(type) {
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("unknown private key type, only support *ecdsa.PrivateKey")
		}
	}

	return nil, errors.New("invalid key type, it should be *ecdsa.PrivateKey at least")
}
