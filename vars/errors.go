package vars

import (
	"fmt"
	"reflect"
)

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
