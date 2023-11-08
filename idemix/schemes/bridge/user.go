package bridge

import (
	"fmt"

	"github.com/11090815/hyperchain/common/mathlib"
	"github.com/11090815/hyperchain/idemix/schemes/crypto"
	"github.com/11090815/hyperchain/idemix/schemes/handlers"
)

// User encapsulates the idemix algorithms to generate user secret keys and pseudonym.
type User struct {
	Translator crypto.Translator
	Idemix     *crypto.Idemix
}

// NewKey generates an idemix user secret key
func (u *User) NewKey() (res *mathlib.Zr, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	res = u.Idemix.Curve.NewRandomZr(newRandOrPanic(u.Idemix.Curve))

	return
}

func (u *User) NewKeyFromBytes(raw []byte) (res *mathlib.Zr, err error) {
	if len(raw) != u.Idemix.Curve.FieldBytes {
		return nil, fmt.Errorf("invalid length, expected [%d], got [%d]", u.Idemix.Curve.FieldBytes, len(raw))
	}

	res = u.Idemix.Curve.NewZrFromBytes(raw)

	return
}

// MakeNym generates a new pseudonym key-pair derived from the passed user secret key (sk) and issuer public key (ipk)
func (u *User) MakeNym(sk *mathlib.Zr, ipk handlers.IssuerPublicKey) (r1 *mathlib.G1, r2 *mathlib.Zr, err error) {
	defer func() {
		if r := recover(); r != nil {
			r1 = nil
			r2 = nil
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	iipk, ok := ipk.(*IssuerPublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	ecp, big, err := u.Idemix.MakeNym(sk, iipk.PK, newRandOrPanic(u.Idemix.Curve), u.Translator)

	r1 = ecp
	r2 = big

	return
}

// MakeNym generates a new pseudonym key-pair derived from the passed user secret key (sk) and issuer public key (ipk)
func (u *User) NewNymFromBytes(raw []byte) (r1 *mathlib.G1, r2 *mathlib.Zr, err error) {
	defer func() {
		if r := recover(); r != nil {
			r1 = nil
			r2 = nil
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	ecp, big, err := u.Idemix.MakeNymFromBytes(raw)
	r1 = ecp
	r2 = big

	return
}

func (u *User) NewPublicNymFromBytes(raw []byte) (res *mathlib.G1, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = fmt.Errorf("failure [%s]", r)
		}
	}()

	res, err = u.Translator.G1FromRawBytes(raw)

	return
}
