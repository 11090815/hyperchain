package identity

import (
	"fmt"
	"testing"

	"github.com/11090815/hyperchain/vars"
)

func func1() error {
	return vars.NewPathError("err from func1")
}

func func2() error {
	err := func1()
	return vars.NewPathError(fmt.Sprintf("err from func2: %s", err.Error()))
}

func func3() error {
	err := func2()
	return vars.NewPathError(fmt.Sprintf("err from func3: %s", err.Error()))
}

func TestPathError(t *testing.T) {
	err := func3()
	fmt.Println(err.Error())
}
