package vars

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
)

const PrefixPath = "github.com/11090815/"

type PathError struct {
	err  string
	path string
}

func (pe PathError) Error() string {
	return fmt.Sprintf("[%s] => {%s}", pe.path, pe.err)
}

func NewPathError(err string) PathError {
	pc, file, line, ok := runtime.Caller(1)
	if !ok {
		return PathError{
			err:  err,
			path: "unknown path",
		}
	}

	index := strings.Index(file, PrefixPath)
	if index == -1 {
		file = "unknown file"
	} else {
		file = file[index+len(PrefixPath):]
	}
	
	funcName := runtime.FuncForPC(pc).Name()
	index = strings.LastIndex(funcName, ".")
	if index == -1 {
		funcName = "unknown function"
	} else {
		funcName = funcName[index+1:]
	}
	
	return PathError{
		err:  err,
		path: fmt.Sprintf("\"%s\" \"%s\" #%d", file, funcName, line),
	}
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type ErrorDecodePEMFormatCertificate struct {
	BlockIsNil    bool
	RestIsNotNil  bool
	MaterialIsNil bool
}

func (err ErrorDecodePEMFormatCertificate) Error() string {
	if err.BlockIsNil {
		return "failed converting PEM-encoded certificate to ASN.1 DER"
	}
	if err.RestIsNotNil {
		return "decoding PEM-encoded certificate may be failed, because rest is not nil"
	}
	if err.MaterialIsNil {
		return "if you want to converting PEM-encoded certificate to ASN.1 DER, you should provide non-nil material raw"
	}
	return ""
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type ErrorDecodePEMFormatKey struct {
	BlockIsNil    bool
	RestIsNotNil  bool
	MaterialIsNil bool
}

func (err ErrorDecodePEMFormatKey) Error() string {
	if err.BlockIsNil {
		return "failed converting PEM-encoded key to ASN.1 DER"
	}
	if err.RestIsNotNil {
		return "decoding PEM-encoded key may be failed, because rest is not nil"
	}
	if err.MaterialIsNil {
		return "if you want to converting PEM-encoded key to ASN.1 DER, you should provide non-nil material raw"
	}
	return ""
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type ErrorGettingHashOption struct {
	Reason string
}

func (err ErrorGettingHashOption) Error() string {
	return fmt.Sprintf("failed getting hash function option: [%s]", err.Reason)
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type ErrorShouldNotBeNil struct {
	Type reflect.Type
}

func (err ErrorShouldNotBeNil) Error() string {
	return fmt.Sprintf("%s should not be nil", err.Type.String())
}
