package crypto

import (
	"io"

	"github.com/11090815/hyperchain/common/mathlib"
	"errors"
)

// wbbKeyGen creates a fresh weak-Boneh-Boyen signature key pair (http://ia.cr/2004/171)
func wbbKeyGen(curve *mathlib.Curve, rng io.Reader) (*mathlib.Zr, *mathlib.G2) {
	// sample sk uniform from Zq
	sk := curve.NewRandomZr(rng)
	// set pk = g2^sk
	pk := curve.GenG2.Mul(sk)
	return sk, pk
}

// wbbSign places a weak Boneh-Boyen signature on message m using secret key sk
func wbbSign(curve *mathlib.Curve, sk *mathlib.Zr, m *mathlib.Zr) *mathlib.G1 {
	// compute exp = 1/(m + sk) mod q
	exp := curve.ModAdd(sk, m, curve.GroupOrder)
	exp.InvModP(curve.GroupOrder)

	// return signature sig = g1^(1/(m + sk))
	return curve.GenG1.Mul(exp)
}

// wbbVerify verifies a weak Boneh-Boyen signature sig on message m with public key pk
func wbbVerify(curve *mathlib.Curve, pk *mathlib.G2, sig *mathlib.G1, m *mathlib.Zr) error {
	if pk == nil || sig == nil || m == nil {
		return errors.New("weak-bb signature invalid: received nil input")
	}
	// Set P = pk * g2^m
	P := curve.NewG2()
	P.Clone(pk)
	P.Add(curve.GenG2.Mul(m))
	P.Affine()
	// check that e(sig, pk * g2^m) = e(g1, g2)
	if !curve.FExp(curve.Pairing(P, sig)).Equals(curve.GenGt) {
		return errors.New("weak-bb signature is invalid")
	}
	return nil
}
