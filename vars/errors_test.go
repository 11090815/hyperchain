package vars_test

import (
	"reflect"
	"testing"

	"github.com/11090815/hyperchain/vars"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
)

func TestErrorShouldNotBeNil(t *testing.T) {
	var principal *pbmsp.MSPPrincipal
	err := vars.ErrorShouldNotBeNil{Type: reflect.TypeOf(principal)}
	t.Log(err.Error())
}
