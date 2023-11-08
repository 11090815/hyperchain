package bridge

import (
	"crypto/ecdsa"
	"fmt"

	"errors"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/common/mathlib"
	"github.com/11090815/hyperchain/idemix/schemes/crypto"
	"github.com/11090815/hyperchain/idemix/schemes/handlers"
	"google.golang.org/protobuf/proto"
)

// SignatureScheme encapsulates the idemix algorithms to sign and verify using an idemix credential.
type SignatureScheme struct {
	Translator crypto.Translator
	Idemix     *crypto.Idemix
}

// Sign produces an idemix-signature with the respect to the passed serialised credential (cred),
// user secret key (sk), pseudonym public key (Nym) and secret key (RNym), issuer public key (ipk),
// and attributes to be disclosed.
func (s *SignatureScheme) Sign(cred []byte, sk *mathlib.Zr, Nym *mathlib.G1, RNym *mathlib.Zr, ipk handlers.IssuerPublicKey, attributes []bccsp.IdemixAttribute,
	msg []byte, rhIndex, eidIndex int, criRaw []byte, sigType bccsp.SignatureType) (res []byte, meta *bccsp.IdemixSignerMetadata, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	iipk, ok := ipk.(*IssuerPublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	credential := &crypto.Credential{}
	err = proto.Unmarshal(cred, credential)
	if err != nil {
		return nil, nil, fmt.Errorf("failed unmarshalling credential: [%s]", err.Error())
	}

	cri := &crypto.CredentialRevocationInformation{}
	err = proto.Unmarshal(criRaw, cri)
	if err != nil {
		return nil, nil, fmt.Errorf("failed unmarshalling credential revocation information: [%s]", err.Error())
	}

	disclosure := make([]byte, len(attributes))
	for i := 0; i < len(attributes); i++ {
		if attributes[i].Type == bccsp.IdemixHiddenAttribute {
			disclosure[i] = 0
		} else {
			disclosure[i] = 1
		}
	}

	sig, meta, err := s.Idemix.NewSignature(
		credential,
		sk,
		Nym,
		RNym,
		iipk.PK,
		disclosure,
		msg,
		rhIndex, eidIndex,
		cri,
		newRandOrPanic(s.Idemix.Curve),
		s.Translator,
		sigType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating new signature: [%s]", err.Error())
	}

	sigBytes, err := proto.Marshal(sig)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling error: [%s]", err.Error())
	}

	return sigBytes, meta, nil
}

func (s *SignatureScheme) AuditNymEid(
	ipk handlers.IssuerPublicKey,
	eidIndex int,
	signature []byte,
	enrollmentID string,
	RNymEid *mathlib.Zr,
) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	iipk, ok := ipk.(*IssuerPublicKey)
	if !ok {
		return fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	sig := &crypto.Signature{}
	err = proto.Unmarshal(signature, sig)
	if err != nil {
		return err
	}

	eidAttr := s.Idemix.Curve.HashToZr([]byte(enrollmentID))

	return sig.AuditNymEid(
		iipk.PK,
		eidAttr,
		eidIndex,
		RNymEid,
		s.Idemix.Curve,
		s.Translator,
	)
}

// Verify checks that an idemix signature is valid with the respect to the passed issuer public key, digest, attributes,
// revocation index (rhIndex), revocation public key, and epoch.
func (s *SignatureScheme) Verify(
	ipk handlers.IssuerPublicKey,
	signature, digest []byte,
	attributes []bccsp.IdemixAttribute,
	rhIndex, eidIndex int,
	revocationPublicKey *ecdsa.PublicKey,
	epoch int,
	verType bccsp.VerificationType,
	meta *bccsp.IdemixSignerMetadata,
) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	iipk, ok := ipk.(*IssuerPublicKey)
	if !ok {
		return fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	sig := &crypto.Signature{}
	err = proto.Unmarshal(signature, sig)
	if err != nil {
		return err
	}

	disclosure := make([]byte, len(attributes))
	attrValues := make([]*mathlib.Zr, len(attributes))
	for i := 0; i < len(attributes); i++ {
		switch attributes[i].Type {
		case bccsp.IdemixHiddenAttribute:
			disclosure[i] = 0
			attrValues[i] = nil
		case bccsp.IdemixBytesAttribute:
			disclosure[i] = 1
			attrValues[i] = s.Idemix.Curve.HashToZr(attributes[i].Value.([]byte))
		case bccsp.IdemixIntAttribute:
			var value int64
			if v, ok := attributes[i].Value.(int); ok {
				value = int64(v)
			} else if v, ok := attributes[i].Value.(int64); ok {
				value = v
			} else {
				return errors.New("invalid int type for IdemixIntAttribute attribute")
			}

			disclosure[i] = 1
			attrValues[i] = s.Idemix.Curve.NewZrFromInt(value)
		default:
			err = fmt.Errorf("attribute type not allowed or supported [%v] at position [%d]", attributes[i].Type, i)
		}
	}
	if err != nil {
		return
	}

	return sig.Ver(
		disclosure,
		iipk.PK,
		digest,
		attrValues,
		rhIndex,
		eidIndex,
		revocationPublicKey,
		epoch,
		s.Idemix.Curve,
		s.Translator,
		verType,
		meta,
	)
}
