package idemix

import "fmt"

type IdemixIIssuerPublicKeyImporterErrorType int

const (
	IdemixIssuerPublicKeyImporterUnmarshallingError IdemixIIssuerPublicKeyImporterErrorType = iota
	IdemixIssuerPublicKeyImporterHashError
	IdemixIssuerPublicKeyImporterValidationError
	IdemixIssuerPublicKeyImporterNumAttributesError
	IdemixIssuerPublicKeyImporterAttributeNameError
)

type IdemixIssuerPublicKeyImporterError struct {
	Type     IdemixIIssuerPublicKeyImporterErrorType
	ErrorMsg string
	Cause    error
}

func (r *IdemixIssuerPublicKeyImporterError) Error() string {
	if r.Cause != nil {
		return fmt.Sprintf("%s: %s", r.ErrorMsg, r.Cause)
	}

	return r.ErrorMsg
}
