package bridge

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/common/mathlib"
	"github.com/11090815/hyperchain/idemix/schemes/crypto"
	"google.golang.org/protobuf/proto"
)

// Revocation encapsulates the idemix algorithms for revocation
type Revocation struct {
	Translator crypto.Translator
	Idemix     *crypto.Idemix
}

// NewKey generate a new revocation key-pair.
func (r *Revocation) NewKey() (*ecdsa.PrivateKey, error) {
	return r.Idemix.GenerateLongTermRevocationKey()
}

func (r *Revocation) NewKeyFromBytes(raw []byte) (*ecdsa.PrivateKey, error) {
	return r.Idemix.LongTermRevocationKeyFromBytes(raw)
}

// Sign generates a new CRI with the respect to the passed unrevoked handles, epoch, and revocation algorithm.
func (r *Revocation) Sign(key *ecdsa.PrivateKey, unrevokedHandles [][]byte, epoch int, alg bccsp.RevocationAlgorithm) (res []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	handles := make([]*mathlib.Zr, len(unrevokedHandles))
	for i := 0; i < len(unrevokedHandles); i++ {
		handles[i] = r.Idemix.Curve.NewZrFromBytes(unrevokedHandles[i])
	}
	cri, err := r.Idemix.CreateCRI(key, handles, epoch, crypto.RevocationAlgorithm(alg), newRandOrPanic(r.Idemix.Curve), r.Translator)
	if err != nil {
		return nil, fmt.Errorf("failed creating CRI: [%s]", err.Error())
	}

	return proto.Marshal(cri)
}

// Verify checks that the passed serialised CRI (criRaw) is valid with the respect to the passed revocation public key,
// epoch, and revocation algorithm.
func (r *Revocation) Verify(pk *ecdsa.PublicKey, criRaw []byte, epoch int, alg bccsp.RevocationAlgorithm) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	cri := &crypto.CredentialRevocationInformation{}
	err = proto.Unmarshal(criRaw, cri)
	if err != nil {
		return err
	}

	return r.Idemix.VerifyEpochPK(
		pk,
		cri.EpochPk,
		cri.EpochPkSig,
		int(cri.Epoch),
		crypto.RevocationAlgorithm(cri.RevocationAlg),
	)
}
