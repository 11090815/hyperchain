package common

import (
	"bytes"
	"encoding/hex"
	"sync/atomic"
)

// PKIid 的计算方法如下所示：
//  1. 对 api.PeerIdentity 进行 protobuf 的反序列化，得到 *pbmsp.SerializedIdentity{mspid, cert}；
//  2. 然后计算 sha256.Sum(mspid||cert)，其中 mspid 是 msp 的 id，cert 是节点的 ASN.1 DER PEM 格式的 x509 证书；
//  3. 将第二步得到的值作为 PKIid。
type PKIid []byte

func (id PKIid) String() string {
	if len(id) == 0 {
		return "<nil>"
	}
	return hex.EncodeToString(id)
}

func (id PKIid) Equal(other PKIid) bool {
	return bytes.Equal(id, other)
}

func StrToPKIid(idStr string) PKIid {
	id, err := hex.DecodeString(idStr)
	if err != nil {
		panic(err)
	}
	return id
}

func PKIidToStr(id []byte) string {
	return hex.EncodeToString(id)
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

// MessageReplacingPolicy 返回：
// MESSAGE_INVALIDATES（如果该消息使那条消息无效）；
// MESSAGE_INVALIDATED（如果此消息被那条该消息搞得无效）；
// MESSAGE_NO_ACTION。
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

// MessageAcceptor 是一个谓词，用于确定创建 MessageAcceptor 实例的订阅者对哪些消息感兴趣。
type MessageAcceptor func(interface{}) bool

type TLSCertificates struct {
	TLSServerCert atomic.Value
	TLSClientCert atomic.Value
}
