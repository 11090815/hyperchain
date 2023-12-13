package protoutil

import (
	pbcommon "github.com/11090815/hyperchain/protos-go/common"
)

// GetEnvelopeFromBlock 区块的数据部分，每条数据都是 Envelope 的 protobuf 编码后的结果，
// 此方法就是通过反序列化将区块中的单条数据反序列化成一个 Envelope。
func GetEnvelopeFromBlock(data []byte) (*pbcommon.Envelope, error) {
	return UnmarshalEnvelope(data)
}
