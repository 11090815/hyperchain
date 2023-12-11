package protoutil

// SignedData 用于表示验证签名所需的常规三元组。这旨在跨加密方案通用，
// 而大多数加密方案将在数据中包含签名标识和随机数，这留给加密实现。
type SignedData struct {
	Data      []byte
	Identity  []byte // proto.Marshal(*pbmsp.SerializedIdentity)
	Signature []byte
}
