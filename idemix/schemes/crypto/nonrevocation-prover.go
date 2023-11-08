package crypto

import (
	"fmt"
	"io"

	"github.com/11090815/hyperchain/common/mathlib"
)

// nonRevokedProver is the Prover of the ZK proof system that handles revocation.
type nonRevokedProver interface {
	// getFSContribution returns the non-revocation contribution to the Fiat-Shamir hash, forming the challenge of the ZKP,
	getFSContribution(rh *mathlib.Zr, rRh *mathlib.Zr, cri *CredentialRevocationInformation, rng io.Reader) ([]byte, error)

	// getNonRevokedProof returns a proof of non-revocation with the respect to passed challenge
	getNonRevokedProof(chal *mathlib.Zr) (*NonRevocationProof, error)
}

// nopNonRevokedProver is an empty nonRevokedProver
type nopNonRevokedProver struct{}

func (prover *nopNonRevokedProver) getFSContribution(rh *mathlib.Zr, rRh *mathlib.Zr, cri *CredentialRevocationInformation, rng io.Reader) ([]byte, error) {
	return nil, nil
}

func (prover *nopNonRevokedProver) getNonRevokedProof(chal *mathlib.Zr) (*NonRevocationProof, error) {
	ret := &NonRevocationProof{}
	ret.RevocationAlg = int32(ALG_NO_REVOCATION)
	return ret, nil
}

// getNonRevocationProver returns the nonRevokedProver bound to the passed revocation algorithm
func getNonRevocationProver(algorithm RevocationAlgorithm) (nonRevokedProver, error) {
	switch algorithm {
	case ALG_NO_REVOCATION:
		return &nopNonRevokedProver{}, nil
	default:
		// unknown revocation algorithm
		return nil, fmt.Errorf("unknown revocation algorithm %d", algorithm)
	}
}
