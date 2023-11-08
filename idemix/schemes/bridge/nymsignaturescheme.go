package bridge

import (
	"fmt"

	"github.com/11090815/hyperchain/common/mathlib"
	"github.com/11090815/hyperchain/idemix/schemes/crypto"
	"github.com/11090815/hyperchain/idemix/schemes/handlers"

	"google.golang.org/protobuf/proto"
)

// NymSignatureScheme encapsulates the idemix algorithms to sign and verify using an idemix
// pseudonym.
type NymSignatureScheme struct {
	Translator crypto.Translator
	Idemix     *crypto.Idemix
}

// Sign produces a signature over the passed digest. It takes in input, the user secret key (sk),
// the pseudonym public key (Nym) and secret key (RNym), and the issuer public key (ipk).
func (n *NymSignatureScheme) Sign(sk *mathlib.Zr, Nym *mathlib.G1, RNym *mathlib.Zr, ipk handlers.IssuerPublicKey, digest []byte) (res []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	iipk, ok := ipk.(*IssuerPublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	sig, err := n.Idemix.NewNymSignature(
		sk,
		Nym,
		RNym,
		iipk.PK,
		digest,
		newRandOrPanic(n.Idemix.Curve),
		n.Translator)
	if err != nil {
		return nil, fmt.Errorf("failed creating new nym signature: [%s]", err)
	}

	return proto.Marshal(sig)
}

// Verify checks that the passed signatures is valid with the respect to the passed digest, issuer public key,
// and pseudonym public key.
func (n *NymSignatureScheme) Verify(ipk handlers.IssuerPublicKey, Nym *mathlib.G1, signature, digest []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	iipk, ok := ipk.(*IssuerPublicKey)
	if !ok {
		return fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	sig := &crypto.NymSignature{}
	err = proto.Unmarshal(signature, sig)
	if err != nil {
		return fmt.Errorf("error unmarshalling signature: [%s]", err.Error())
	}

	return sig.Ver(Nym, iipk.PK, digest, n.Idemix.Curve, n.Translator)
}
