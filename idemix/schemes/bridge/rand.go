package bridge

import (
	"io"

	"github.com/11090815/hyperchain/common/mathlib"
)

func newRandOrPanic(curve *mathlib.Curve) io.Reader {
	rng, err := curve.Rand()
	if err != nil {
		panic(err)
	}
	return rng
}
