package election

import (
	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/gossip/discovery"
	"github.com/11090815/hyperchain/gossip/protoext"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
)

type gossip interface {
	// 返回给定通道中 alive 的成员信息。
	PeersOfChannel(channel common.ChannelID) []discovery.NetworkMember

	// Accept 返回一个专用的只读通道，用于接收其他节点发送的符合特定谓词的信息。
	// 如果 passThrough 为 false，则消息会事先由 gossip 层处理。
	// 如果 passThrough 为 true，则 gossip 层不会介入，信息可用于向发送者发送回复。
	Accept(acceptor common.MessageAcceptor, passThrough bool) (<-chan *pbgossip.GossipMessage, <-chan protoext.ReceivedMessage)

	// Gossip 向全网广播消息。
	Gossip(msg *pbgossip.GossipMessage)

	// IsInMyOrg 检查给定的成员是否与我在同一组织。
	IsInMyOrg(member discovery.NetworkMember) bool
}
