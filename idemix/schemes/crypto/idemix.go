package crypto

import "github.com/11090815/hyperchain/common/mathlib"

type Idemix struct {
	Curve      *mathlib.Curve
	Translator Translator
}
