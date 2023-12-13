package protoext

import (
	"bytes"

	"github.com/11090815/hyperchain/gossip/common"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
)

type msgComparator struct {
	dataBlockStorageSize int
}

// NewGossipMessageComparator 返回的不是一个结构体，而是一个函数，用于比较两个 gossip 消息。
func NewGossipMessageComparator(dataBlockStorageSize int) common.MessageReplacingPolicy {
	return (&msgComparator{dataBlockStorageSize: dataBlockStorageSize}).getMsgReplacingPolicy()
}

func (mc *msgComparator) getMsgReplacingPolicy() common.MessageReplacingPolicy {
	return func(this, that interface{}) common.InvalidationResult {
		return mc.invalidationPolicy(this, that)
	}
}

func (mc *msgComparator) invalidationPolicy(this interface{}, that interface{}) common.InvalidationResult {
	thisMsg := this.(*SignedGossipMessage)
	thatMsg := that.(*SignedGossipMessage)

	if thisMsg.GossipMessage.GetAliveMsg() != nil && thatMsg.GossipMessage.GetAliveMsg() != nil {
		return aliveInvalidationPolicy(thisMsg.GossipMessage.GetAliveMsg(), thatMsg.GossipMessage.GetAliveMsg())
	}

	if thisMsg.GossipMessage.GetDataMsg() != nil && thatMsg.GossipMessage.GetDataMsg() != nil {
		return mc.dataInvalidationPolicy(thisMsg.GossipMessage.GetDataMsg(), thatMsg.GossipMessage.GetDataMsg())
	}

	if thisMsg.GossipMessage.GetStateInfo() != nil && thatMsg.GossipMessage.GetStateInfo() != nil {
		return mc.stateInvalidationPolicy(thisMsg.GossipMessage.GetStateInfo(), thatMsg.GossipMessage.GetStateInfo())
	}

	if thisMsg.GossipMessage.GetPeerIdentity() != nil && thatMsg.GossipMessage.GetPeerIdentity() != nil {
		return mc.identityInvalidationPolicy(thisMsg.GossipMessage.GetPeerIdentity(), thatMsg.GossipMessage.GetPeerIdentity())
	}

	if thisMsg.GossipMessage.GetLeadershipMsg() != nil && thatMsg.GossipMessage.GetLeadershipMsg() != nil {
		return leaderInvalidationPolicy(thisMsg.GossipMessage.GetLeadershipMsg(), thatMsg.GossipMessage.GetLeadershipMsg())
	}

	return common.MessageNoAction
}

// 对于两条反映节点状态信息 StateInfo 的消息 this 与 that，如果 this 代表的节点与 that 消息代表的节点不是同一个节点，
// 则我们认为这两条消息之间不存在相互作用；但是如果 this 与 that 表示的是同一个节点的状态信息，并且 this 消息比 that
// 消息更新，则我们认为 that 消息过时了，可被认为 that 消息在 this 消息面前是无效的；否则就是 this 消息在 that 消息
// 面前无效。
func (mc *msgComparator) stateInvalidationPolicy(thisState *pbgossip.StateInfo, thatState *pbgossip.StateInfo) common.InvalidationResult {
	if !bytes.Equal(thisState.PkiId, thatState.PkiId) {
		// 如果两个状态消息的身份不相同，则两个状态消息无关
		return common.MessageNoAction
	}
	// 比较两个状态消息的时间
	return compareTimestamp(thisState.Timestamp, thatState.Timestamp)
}

// 对于两条代表节点身份信息 PeerIdentity 的消息 this 与 that，如果 this 消息与 that 消息所代表的节点是同一个节点，
// 那么 this 消息其实就与 that 消息重复了，由于节点身份信息是不变的，所以两条重复的代表节点身份的消息，只需保留一条
// 就行，因此，我们可以认为，this 消息在 that 消息面前就是无效的。
func (mc *msgComparator) identityInvalidationPolicy(thisIdentity *pbgossip.PeerIdentity, thatIdentity *pbgossip.PeerIdentity) common.InvalidationResult {
	if bytes.Equal(thisIdentity.PkiId, thatIdentity.PkiId) {
		// 两个消息的身份相同，那么此消息就是受影响的
		return common.MessageInvalidated
	}

	// 两个消息的身份不相同，则两个消息无关
	return common.MessageNoAction
}

// 对于两条包含区块信息 DataMessage 的消息 this 与 that，如果 this 与 that 中包含的区块相同，则没有必要再去处理 this 消息了，
// 所以 this 消息在 that 消息面前就是无效的；如果 this 消息中的包含的区块比 that 消息中包含的区块老，则 this 消息就相当于过时
// 了，也没必要去处理了，所以 this 消息在 that 消息面前就是无效的，但是存在例外情况，如果 this 消息中存储的区块没有比 that 中
// 的区块老太多，比如，存储区能存储 10 个区块，如果 this 消息中存储的区块只比 that 中存储的区块老 3 代，例如 this 中的区块编号
// 是 4，that 中的区块编号是 7，那么我们可以认为存储 this 消息也是可以的，毕竟存储区能存 10 个区块，所以此时，this 消息可以被
// 认为不受 that 消息的影响。如果 this 消息中存储的区块编号大于 that 中存储的区块，并且是远大于，例如在上面举的例子里，存储区只
// 能存储 10 个区块，但是 this 中的区块编号比 that 中的区块编号大 20，那么此时，that 消息可被认为在 this 消息面前是无效的，可以
// 被删除掉。
func (mc *msgComparator) dataInvalidationPolicy(thisDataMsg *pbgossip.DataMessage, thatDataMsg *pbgossip.DataMessage) common.InvalidationResult {
	if thisDataMsg.Payload.SeqNum == thatDataMsg.Payload.SeqNum {
		// 如果两个区块的序号相同，则此区块是受影响的
		return common.MessageInvalidated
	}

	diff := abs(thisDataMsg.Payload.SeqNum, thatDataMsg.Payload.SeqNum)
	if diff <= uint64(mc.dataBlockStorageSize) {
		// 如果两个区块之间的序号差在一定范围内，则两个区块无关
		return common.MessageNoAction
	}

	// 如果本区块的序号大于另一个区块，则本区块影响另一个区块
	if thisDataMsg.Payload.SeqNum > thatDataMsg.Payload.SeqNum {
		return common.MessageInvalidates
	}

	// 如果本区块的序号小于另一个区块，则本区块受影响
	return common.MessageInvalidated
}

// 对于两条反映节点活跃状态信息 AliveMessage 的消息 this 与 that，如果 this 与 that 代表的节点不同，则认为 this 消息与 that 消息
// 之间不存在相互作用；由于节点的活跃状态信息是可能随着时间变化的，因此，如果 this 消息比 that 消息新，则可认为 that 消息在 this 消
// 息面前是无效的，否则就是 this 消息在 that 消息面前是无效的。
func aliveInvalidationPolicy(thisMsg *pbgossip.AliveMessage, thatMsg *pbgossip.AliveMessage) common.InvalidationResult {
	if !bytes.Equal(thisMsg.Membership.PkiId, thatMsg.Membership.PkiId) {
		return common.MessageNoAction
	}

	return compareTimestamp(thisMsg.Timestamp, thatMsg.Timestamp)
}

// 对于两条竞选领导者的消息 LeadershipMessage，如果 this 消息中领导者的 id 与 that 消息中的领导者身份不一样，则说明这两条消息之间
// 不会相互影响；但是如果两条消息中声明的领导者的 id 相同，那么如果 this 消息的时间戳比 that 消息的时间戳更新，那么 that 消息则会被
// 视为无效的消息，如果 that 消息已被存储在消息存储区中，则应该被删除，用 this 消息去替代它；同样地，如果 this 消息的时间戳比 that 消
// 息的时间戳更老，则 this 消息是无效的。
func leaderInvalidationPolicy(thisMsg *pbgossip.LeadershipMessage, thatMsg *pbgossip.LeadershipMessage) common.InvalidationResult {
	if !bytes.Equal(thisMsg.PkiId, thatMsg.PkiId) {
		return common.MessageNoAction // 两条领导者竞选消息的领导者 id 不同，则两条消息不相干
	}
	return compareTimestamp(thisMsg.Timestamp, thatMsg.Timestamp)
}

func compareTimestamp(thisTS *pbgossip.PeerTime, thatTS *pbgossip.PeerTime) common.InvalidationResult {
	if thisTS.IncNum == thatTS.IncNum {
		if thisTS.SeqNum > thatTS.SeqNum {
			return common.MessageInvalidates
		}

		return common.MessageInvalidated
	}

	if thisTS.IncNum < thatTS.IncNum {
		return common.MessageInvalidated
	}
	return common.MessageInvalidates
}

// abs 返回 |a-b|
func abs(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
