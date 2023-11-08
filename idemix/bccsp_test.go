package idemix_test

import (
	"crypto/sha256"
	"testing"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/common/mathlib"
	"github.com/11090815/hyperchain/idemix"
	"github.com/11090815/hyperchain/idemix/keystore"
	"github.com/11090815/hyperchain/idemix/schemes/crypto/translator"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	trans := &translator.Gurvy{C: mathlib.Curves[0]}
	ks, err := keystore.NewKVSStore("testdata", trans, mathlib.Curves[0])
	require.NoError(t, err)
	csp, err := idemix.New(ks, mathlib.Curves[0], trans, true)
	require.NoError(t, err)
	require.NotNil(t, csp)

	key, err := csp.KeyGen(&bccsp.IdemixIssuerKeyGenOpts{Temporary: true, AttributeNames: []string{"name=wxy", "age=25", "address=hf", "career=student"}})
	require.NoError(t, err)

	msg := []byte("hello")
	digest := sha256.Sum256(msg)
	sig, err := csp.Sign(key, digest[:], &bccsp.IdemixCredentialSignerOpts{})
	require.NoError(t, err)
	require.NotNil(t, sig)
}
