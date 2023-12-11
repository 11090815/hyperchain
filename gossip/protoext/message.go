package protoext

import (
	"fmt"

	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
)

// GetPullMsgType 属于 pull 机制的 GossipMessage，返回此类消息的 PullMsgType：BLOCK_MSG IDENTITY_MSG UNDEFINED。
func GetPullMsgType(m *pbgossip.GossipMessage) pbgossip.PullMsgType {
	if m.GetHello() != nil {
		return m.GetHello().MsgType
	}

	if m.GetDataDig() != nil {
		return m.GetDataDig().MsgType
	}

	if m.GetDataReq() != nil {
		return m.GetDataReq().MsgType
	}

	if m.GetDataUpdate() != nil {
		return m.GetDataUpdate().MsgType
	}

	return pbgossip.PullMsgType_UNDEFINED
}

// IsPullMsg 判断给定的消息是否是以下四种消息的一种：
//   - GossipHello
//   - DataRequest
//   - DataUpdate
//   - DataDigest
func IsPullMsg(m *pbgossip.GossipMessage) bool {
	return m.GetHello() != nil || m.GetDataReq() != nil || m.GetDataUpdate() != nil || m.GetDataDig() != nil
}

// IsChannelRestricted 判断给定的消息是否只在其通道 channel 内路由：
//   - GossipMessage_CHAN_AND_ORG
//   - GossipMessage_CHAN_ONLY
//   - GossipMessage_CHAN_OR_ORG
func IsChannelRestricted(m *pbgossip.GossipMessage) bool {
	return m.Tag == pbgossip.GossipMessage_CHAN_AND_ORG ||
		m.Tag == pbgossip.GossipMessage_CHAN_ONLY ||
		m.Tag == pbgossip.GossipMessage_CHAN_OR_ORG
}

// IsOrgRestricted 判断给定的消息是否只在其组织 org 内被路由：
//   - GossipMessage_CHAN_AND_ORG
//   - GossipMessage_ORG_ONLY
func IsOrgRestricted(m *pbgossip.GossipMessage) bool {
	return m.Tag == pbgossip.GossipMessage_CHAN_AND_ORG ||
		m.Tag == pbgossip.GossipMessage_ORG_ONLY
}

func IsTagLegal(m *pbgossip.GossipMessage) error {
	if m.Tag == pbgossip.GossipMessage_UNDEFINED {
		return fmt.Errorf("undefined tag")
	}

	if m.GetDataMsg() != nil {
		if m.Tag != pbgossip.GossipMessage_CHAN_AND_ORG {
			return fmt.Errorf("DataMessage should with tag [%s]", pbgossip.GossipMessage_CHAN_AND_ORG.String())
		}
		return nil
	}

	if m.GetAliveMsg() != nil || m.GetMemReq() != nil || m.GetMemRes() != nil {
		if m.Tag != pbgossip.GossipMessage_EMPTY {
			if m.GetAliveMsg() != nil {
				return fmt.Errorf("AliveMessage should with tag [%s]", pbgossip.GossipMessage_EMPTY.String())
			} else if m.GetMemReq() != nil {
				return fmt.Errorf("MembershipRequest should with tag [%s]", pbgossip.GossipMessage_EMPTY.String())
			} else if m.GetMemRes() != nil {
				return fmt.Errorf("MembershipResponse should with tag [%s]", pbgossip.GossipMessage_EMPTY.String())
			}
		}
		return nil
	}

	if m.GetPeerIdentity() != nil {
		if m.Tag != pbgossip.GossipMessage_ORG_ONLY {
			return fmt.Errorf("PeerIdentity should with tag [%s]", pbgossip.GossipMessage_ORG_ONLY.String())
		}
		return nil
	}

	if IsPullMsg(m) {
		switch GetPullMsgType(m) {
		case pbgossip.PullMsgType_BLOCK_MSG:
			if m.Tag != pbgossip.GossipMessage_CHAN_AND_ORG {
				return fmt.Errorf("GossipMessage with pull type [%s] should have tag [%s]", pbgossip.PullMsgType_BLOCK_MSG.String(), pbgossip.GossipMessage_CHAN_AND_ORG.String())
			}
			return nil
		case pbgossip.PullMsgType_IDENTITY_MSG:
			if m.Tag != pbgossip.GossipMessage_EMPTY {
				return fmt.Errorf("GossipMessage with pull type [%s] should have tag [%s]", pbgossip.PullMsgType_IDENTITY_MSG.String(), pbgossip.GossipMessage_EMPTY.String())
			}
			return nil
		default:
			return fmt.Errorf("invalid pull msg type [%s]", GetPullMsgType(m).String())
		}
	}

	if m.GetStateInfo() != nil || m.GetStateInfoPullReq() != nil || m.GetStateSnapshot() != nil || m.GetStateRequest() != nil || m.GetStateResponse() != nil {
		if m.Tag != pbgossip.GossipMessage_CHAN_OR_ORG {
			if m.GetStateInfo() != nil {
				return fmt.Errorf("StateInfo should with tag [%s]", pbgossip.GossipMessage_CHAN_OR_ORG.String())
			} else if m.GetStateInfoPullReq() != nil {
				return fmt.Errorf("StateInfoPullRequest should with tag [%s]", pbgossip.GossipMessage_CHAN_OR_ORG.String())
			} else if m.GetStateSnapshot() != nil {
				return fmt.Errorf("StateInfoSnapshot should with tag [%s]", pbgossip.GossipMessage_CHAN_OR_ORG.String())
			} else if m.GetStateRequest() != nil {
				return fmt.Errorf("RemoteStateRequest should with tag [%s]", pbgossip.GossipMessage_CHAN_OR_ORG.String())
			} else if m.GetStateResponse() != nil {
				return fmt.Errorf("RemoteStateResponse should with tag [%s]", pbgossip.GossipMessage_CHAN_OR_ORG.String())
			}
		}
		return nil
	}

	if m.GetLeadershipMsg() != nil {
		if m.Tag != pbgossip.GossipMessage_CHAN_AND_ORG {
			return fmt.Errorf("LeadershipMessage should with tag [%s]", pbgossip.GossipMessage_CHAN_AND_ORG.String())
		}
		return nil
	}

	return fmt.Errorf("unknown message type [%v]", m)
}
