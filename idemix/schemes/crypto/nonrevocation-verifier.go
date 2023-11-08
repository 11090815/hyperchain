package crypto

import (
	"fmt"

	"github.com/11090815/hyperchain/common/mathlib"
)

// nonRevokedProver is the Verifier of the ZK proof system that handles revocation.
type nonRevocationVerifier interface {
	// recomputeFSContribution recomputes the contribution of the non-revocation proof to the ZKP challenge
	recomputeFSContribution(proof *NonRevocationProof, chal *mathlib.Zr, epochPK *mathlib.G2, proofSRh *mathlib.Zr) ([]byte, error)
}

// nopNonRevocationVerifier is an empty nonRevocationVerifier that produces an empty contribution
type nopNonRevocationVerifier struct{}

func (verifier *nopNonRevocationVerifier) recomputeFSContribution(proof *NonRevocationProof, chal *mathlib.Zr, epochPK *mathlib.G2, proofSRh *mathlib.Zr) ([]byte, error) {
	return nil, nil
}

// getNonRevocationVerifier returns the nonRevocationVerifier bound to the passed revocation algorithm
func getNonRevocationVerifier(algorithm RevocationAlgorithm) (nonRevocationVerifier, error) {
	switch algorithm {
	case ALG_NO_REVOCATION:
		return &nopNonRevocationVerifier{}, nil
	default:
		// unknown revocation algorithm
		return nil, fmt.Errorf("unknown revocation algorithm %d", algorithm)
	}
}
