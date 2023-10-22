package sw

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/11090815/hyperchain/bccsp"
)

type KeyDeriver interface {
	KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (dkey bccsp.Key, err error)
}

type ecdsaPublicKeyDeriver struct{}

// KeyDeriv 提供的 bccsp.Key 的实际类型必须是 *ecdsaPublicKey。
func (*ecdsaPublicKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	if opts == nil {
		return nil, errors.New("invalid opts: [it shouldn't be nil]")
	}

	reRandOpts, ok := opts.(*bccsp.ECDSAKeyDerivOpts)
	if !ok {
		return nil, fmt.Errorf("want *bccsp.ECDSAReRandOpts, but got [%T]", opts)
	}

	publicKey := key.(*ecdsaPublicKey)

	tempPK := &ecdsa.PublicKey{
		Curve: publicKey.publicKey.Curve,
		X:     new(big.Int),
		Y:     new(big.Int),
	}

	// k = k mod (N-1)
	// k = k + 1
	// (x_k, y_k) = k * G
	// pk = pk + k * G    (x_new, y_new) = (x_old, y_old) + (x_k, y_k)
	k := new(big.Int).SetBytes(reRandOpts.ExpansionValue()) // 将扩展值转换为数字
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(publicKey.publicKey.Params().N, one)
	k.Mod(k, n)
	k.Add(k, one)

	tempX, tempY := publicKey.publicKey.ScalarBaseMult(k.Bytes())
	tempPK.X, tempPK.Y = tempPK.Add(publicKey.publicKey.X, publicKey.publicKey.Y, tempX, tempY)

	if !tempPK.IsOnCurve(tempPK.X, tempPK.Y) {
		return nil, errors.New("the derived public key is not on the curve")
	}

	return &ecdsaPublicKey{publicKey: tempPK}, nil
}

/*** 🐋 ***/

type ecdsaPrivateKeyDeriver struct{}

// KeyDeriv 传入的 bccsp.Key 的类型必须是 *ecdsaPublicKey。
func (*ecdsaPrivateKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	if opts == nil {
		return nil, errors.New("invalid opts: [it shouldn't be nil]")
	}

	reRandOpts, ok := opts.(*bccsp.ECDSAKeyDerivOpts)
	if !ok {
		return nil, fmt.Errorf("want *bccsp.ECDSAReRandOpts, but got [%T]", opts)
	}

	privateKey := key.(*ecdsaPrivateKey)

	tempSK := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: privateKey.privateKey.Curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		},
		D: new(big.Int),
	}

	// sk = sk + k
	// pk = pk + k * G
	k := new(big.Int).SetBytes(reRandOpts.ExpansionValue()) // 将扩展值转换为数字
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(privateKey.privateKey.Curve.Params().N, one)
	k.Mod(k, n)
	k.Add(k, one)

	tempSK.D.Add(privateKey.privateKey.D, k)
	tempSK.D.Mod(tempSK.D, privateKey.privateKey.Params().N)

	tempX, tempY := privateKey.privateKey.ScalarBaseMult(k.Bytes())
	tempSK.PublicKey.X, tempSK.PublicKey.Y = tempSK.Add(tempX, tempY, privateKey.privateKey.X, privateKey.privateKey.Y)

	if !tempSK.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y) {
		return nil, errors.New("the derived public key is not on the curve")
	}

	return &ecdsaPrivateKey{privateKey: tempSK}, nil
}

/*** 🐋 ***/

type aesKeyDeriver struct{}

// KeyDeriv 传入的 bccsp.Key 必须是 *aesPrivateKey
func (*aesKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	if opts == nil {
		return nil, errors.New("invalid opts: [it shouldn't be nil]")
	}

	aesK := key.(*aesKey)

	reRandOpts, ok := opts.(*bccsp.AESKeyDerivOpts)
	if !ok {
		return nil, fmt.Errorf("want *bccsp.AESKeyDerivOpts, but got [%T]", opts)
	}

	mac := hmac.New(sha256.New, aesK.key)
	mac.Write(reRandOpts.Argument())
	return &aesKey{key: mac.Sum(nil), exportable: false}, nil
}
