package crypto

import (
	"io"

	"github.com/11090815/hyperchain/common/mathlib"
	"github.com/11090815/hyperchain/idemix/schemes/crypto/translator"
)

func appendBytes(data []byte, index int, bytesToAdd []byte) int {
	copy(data[index:], bytesToAdd)
	return index + len(bytesToAdd)
}
func appendBytesG1(data []byte, index int, E *mathlib.G1) int {
	return appendBytes(data, index, E.Bytes())
}
func appendBytesG2(data []byte, index int, E *mathlib.G2) int {
	return appendBytes(data, index, E.Bytes())
}
func appendBytesBig(data []byte, index int, B *mathlib.Zr) int {
	return appendBytes(data, index, B.Bytes())
}
func appendBytesString(data []byte, index int, s string) int {
	bytes := []byte(s)
	copy(data[index:], bytes)
	return index + len(bytes)
}

// MakeNym creates a new unlinkable pseudonym
func (i *Idemix) MakeNym(sk *mathlib.Zr, IPk *IssuerPublicKey, rng io.Reader, t Translator) (*mathlib.G1, *mathlib.Zr, error) {
	return makeNym(sk, IPk, rng, i.Curve, t)
}

func makeNym(sk *mathlib.Zr, IPk *IssuerPublicKey, rng io.Reader, curve *mathlib.Curve, t Translator) (*mathlib.G1, *mathlib.Zr, error) {
	// Construct a commitment to the sk
	// Nym = h_{sk}^sk \cdot h_r^r
	RandNym := curve.NewRandomZr(rng)
	HSk, err := t.G1FromProto(IPk.HSk)
	if err != nil {
		return nil, nil, err
	}
	HRand, err := t.G1FromProto(IPk.HRand)
	if err != nil {
		return nil, nil, err
	}
	Nym := HSk.Mul2(sk, HRand, RandNym)
	return Nym, RandNym, nil
}

func (i *Idemix) MakeNymFromBytes(raw []byte) (*mathlib.G1, *mathlib.Zr, error) {
	return makeNymFromBytes(i.Curve, raw, i.Translator)
}

func makeNymFromBytes(curve *mathlib.Curve, raw []byte, trans Translator) (*mathlib.G1, *mathlib.Zr, error) {
	RandNym := curve.NewZrFromBytes(raw[:curve.FieldBytes])
	pk, err := trans.G1FromProto(&translator.ECP{
		X: raw[curve.FieldBytes : 2*curve.FieldBytes],
		Y: raw[2*curve.FieldBytes:],
	})
	if err != nil {
		return nil, nil, err
	}

	return pk, RandNym, nil
}
