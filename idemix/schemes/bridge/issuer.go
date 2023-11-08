package bridge

import (
	"fmt"

	"github.com/11090815/hyperchain/idemix/schemes/crypto"
	"github.com/11090815/hyperchain/idemix/schemes/handlers"
	"google.golang.org/protobuf/proto"
)

// IssuerPublicKey encapsulate an idemix issuer public key.
type IssuerPublicKey struct {
	PK *crypto.IssuerPublicKey
}

func (o *IssuerPublicKey) Bytes() ([]byte, error) {
	return proto.Marshal(o.PK)
}

func (o *IssuerPublicKey) Hash() []byte {
	return o.PK.Hash
}

// IssuerPublicKey encapsulate an idemix issuer secret key.
type IssuerSecretKey struct {
	SK *crypto.IssuerKey
}

func (o *IssuerSecretKey) Bytes() ([]byte, error) {
	return proto.Marshal(o.SK)
}

func (o *IssuerSecretKey) Public() handlers.IssuerPublicKey {
	return &IssuerPublicKey{o.SK.Ipk}
}

// Issuer encapsulates the idemix algorithms to generate issuer key-pairs
type Issuer struct {
	Translator crypto.Translator
	Idemix     *crypto.Idemix
}

// NewKey generates a new issuer key-pair
func (i *Issuer) NewKey(attributeNames []string) (res handlers.IssuerSecretKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	sk, err := i.Idemix.NewIssuerKey(attributeNames, newRandOrPanic(i.Idemix.Curve), i.Translator)
	if err != nil {
		return
	}

	res = &IssuerSecretKey{SK: sk}

	return
}

func (i *Issuer) NewKeyFromBytes(raw []byte, attributes []string) (res handlers.IssuerSecretKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	sk, err := i.Idemix.NewIssuerKeyFromBytes(raw)
	if err != nil {
		return
	}

	res = &IssuerSecretKey{SK: sk}

	return
}

func (i *Issuer) NewPublicKeyFromBytes(raw []byte, attributes []string) (res handlers.IssuerPublicKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	ipk := new(crypto.IssuerPublicKey)
	err = proto.Unmarshal(raw, ipk)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal issuer public key: [%s]", err.Error())
	}

	err = ipk.SetHash(i.Idemix.Curve)
	if err != nil {
		return nil, fmt.Errorf("setting the hash of the issuer public key failed: [%s]", err.Error())
	}

	err = ipk.Check(i.Idemix.Curve, i.Translator)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer public key: [%s]", err.Error())
	}

	if len(attributes) != 0 {
		// Check the attributes
		if len(attributes) != len(ipk.AttributeNames) {
			return nil, fmt.Errorf("invalid number of attributes, expected [%d], got [%d]", len(ipk.AttributeNames), len(attributes))
		}

		for i, attr := range attributes {
			if ipk.AttributeNames[i] != attr {
				return nil, fmt.Errorf("invalid attribute name at position [%d]", i)
			}
		}
	}

	res = &IssuerPublicKey{PK: ipk}

	return
}
