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

func (mc *msgComparator) stateInvalidationPolicy(thisState *pbgossip.StateInfo, thatState *pbgossip.StateInfo) common.InvalidationResult {
	if !bytes.Equal(thisState.PkiId, thatState.PkiId) {
		// 如果两个状态消息的身份不相同，则两个状态消息无关
		return common.MessageNoAction
	}
	// 比较两个状态消息的时间
	return compareTimestamp(thisState.Timestamp, thatState.Timestamp)
}

func (mc *msgComparator) identityInvalidationPolicy(thisIdentity *pbgossip.PeerIdentity, thatIdentity *pbgossip.PeerIdentity) common.InvalidationResult {
	if bytes.Equal(thisIdentity.PkiId, thatIdentity.PkiId) {
		// 两个消息的身份相同，那么此消息就是受影响的
		return common.MessageInvalidated
	}

	// 两个消息的身份不相同，则两个消息无关
	return common.MessageNoAction
}

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

func aliveInvalidationPolicy(thisMsg *pbgossip.AliveMessage, thatMsg *pbgossip.AliveMessage) common.InvalidationResult {
	if !bytes.Equal(thisMsg.Membership.PkiId, thatMsg.Membership.PkiId) {
		return common.MessageNoAction
	}

	return compareTimestamp(thisMsg.Timestamp, thatMsg.Timestamp)
}

func leaderInvalidationPolicy(thisMsg *pbgossip.LeadershipMessage, thatMsg *pbgossip.LeadershipMessage) common.InvalidationResult {
	if !bytes.Equal(thisMsg.PkiId, thatMsg.PkiId) {
		return common.MessageNoAction
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
