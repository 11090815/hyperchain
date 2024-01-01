package protoext

import (
	"fmt"

	"github.com/11090815/hyperchain/gossip/api"
	"github.com/11090815/hyperchain/gossip/common"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
)

// ReceivedMessage 是一种对 GossipMessage 的包装器，该包装器可以让用户向发送消息的节点回复消息，
// 同时它允许用户获晓发送方节点的信息。
type ReceivedMessage interface {
	// Respond 给发送消息的节点回复消息。
	Respond(msg *pbgossip.GossipMessage)

	GetSignedGossipMessage() *SignedGossipMessage

	GetEnvelope() *pbgossip.Envelope

	GetConnectionInfo() *ConnectionInfo

	// 给发送消息的节点一个响应。
	Ack(err error)
}

// ConnectionInfo 表示发送消息的 peer 节点的信息。
type ConnectionInfo struct {
	PKIid    common.PKIid
	Auth     *AuthInfo
	Identity api.PeerIdentity
	Endpoint string
}

func (c *ConnectionInfo) String() string {
	return fmt.Sprintf("%s %v", c.Endpoint, c.PKIid)
}

// AuthInfo 用签名作为认证数据，包括被签署的消息和签名。
type AuthInfo struct {
	SignedData []byte
	Signature  []byte
}
