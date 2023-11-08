package idemix_test

import (
	"reflect"
	"testing"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/common/mathlib"
	"github.com/11090815/hyperchain/idemix"
	"github.com/11090815/hyperchain/idemix/keystore"
	"github.com/11090815/hyperchain/idemix/schemes/bridge"
	"github.com/11090815/hyperchain/idemix/schemes/crypto"
	"github.com/11090815/hyperchain/idemix/schemes/crypto/translator"
	"github.com/11090815/hyperchain/idemix/schemes/handlers"
	"github.com/stretchr/testify/require"
)

func TestNewImpl(t *testing.T) {
	trans := &translator.Gurvy{C: mathlib.Curves[0]}
	ks, err := keystore.NewKVSStore("testdata", trans, mathlib.Curves[0])
	require.NoError(t, err)

	csp, err := idemix.NewImpl(ks)
	require.NoError(t, err)

	idmx := &crypto.Idemix{
		Curve:      mathlib.Curves[0],
		Translator: trans,
	}

	csp.AddWrapper(reflect.TypeOf(&bccsp.IdemixIssuerKeyGenOpts{}), &handlers.IssuerKeyGen{Issuer: &bridge.Issuer{Idemix: idmx, Translator: trans}, Exportable: true})

	key, err := csp.KeyGen(&bccsp.IdemixIssuerKeyGenOpts{Temporary: false, AttributeNames: []string{"name=wxy", "age=25", "address=hf", "career=student"}})
	require.NoError(t, err)
	require.NotNil(t, key)
}
