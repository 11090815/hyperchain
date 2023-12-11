package common

import "encoding/hex"

// PKIid 的计算方法如下所示：
//	1. 对 api.PeerIdentity 进行 protobuf 的反序列化，得到 *pbmsp.SerializedIdentity{mspid, cert}；
//	2. 然后计算 sha256.Sum(mspid||cert)，其中 mspid 是 msp 的 id，cert 是节点的 ASN.1 DER PEM 格式的 x509 证书；
//	3. 将第二步得到的值作为 PKIid。
type PKIid []byte

type MessageReplacingPolicy func(this interface{}, that interface{}) InvalidationResult

type InvalidationResult int

const (
	MessageNoAction InvalidationResult = iota
	// 意味着消息将其他消息弄成无效的了。
	MessageInvalidates
	// 意味着消息被其他消息弄成无效的了。
	MessageInvalidated
)

type ChannelID []byte

// 计算 channel id 的十六进制字符串。
func (c ChannelID) String() string {
	return hex.EncodeToString(c)
}
