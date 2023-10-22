package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}
	return nil, false
}

func privateKeyToPEM(privateKey interface{}) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("invalid key: [it shouldn't be nil]")
	}

	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if key == nil {
			return nil, errors.New("invalid ecdsa private key: [it shouldn't be nil]")
		}

		oidNamedCurve, ok := oidFromNamedCurve(key.Curve)
		if !ok {
			return nil, errors.New("unknown elliptic curve")
		}

		privateKeyBytes := key.D.Bytes()
		paddedPrivateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
		copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)

		asn1Bytes, err := asn1.Marshal(ecPrivateKey{
			Version:    1,
			PrivateKey: paddedPrivateKey,
			PublicKey:  asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
		})
		if err != nil {
			return nil, fmt.Errorf("failed marshaling EC key to asn1: [%s]", err.Error())
		}

		var pkcs8Key pkcs8Info
		pkcs8Key.Version = 0
		pkcs8Key.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 2)
		pkcs8Key.PrivateKeyAlgorithm[0] = oidPublicKeyECDSA
		pkcs8Key.PrivateKeyAlgorithm[1] = oidNamedCurve
		pkcs8Key.PrivateKey = asn1Bytes

		pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key to asn1: [%s]", err)
		}
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: pkcs8Bytes,
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
