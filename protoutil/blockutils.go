package protoutil

import (
	pbcommon "github.com/11090815/hyperchain/protos-go/common"
)

type BlockVerifierFunc func(header *pbcommon.BlockHeader, metadata *pbcommon.BlockMetadata) error

type policy interface {
	EvaluateSignedData(signatures []*SignedData) error
}

func BlockSignatureVerifier(bftEnabled bool, consenters []*pbcommon.Consenter, policy policy) BlockVerifierFunc {
	
}
