package election

import (
	"bytes"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/gossip/discovery"
	"github.com/11090815/hyperchain/gossip/metrics"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
)

type LeaderElectionAdapter interface {
	Gossip(*pbgossip.GossipMessage)

	Accept() <-chan *pbgossip.GossipMessage

	CreateMessage(isDeclaration bool) *pbgossip.GossipMessage

	// Peers 返回与自己在同一组织内的 alive 成员信息。
	Peers() []discovery.NetworkMember

	ReportMetrics(isLeader bool)

	Stop()
}

type adapterImpl struct {
	gossip    gossip
	selfPKIid common.PKIid
	incTime   uint64
	seqNum    uint64

	channel common.ChannelID
	logger  *hlogging.HyperchainLogger

	stopCh  chan struct{}
	metrics *metrics.ElectionMetrics
}

func (impl *adapterImpl) Gossip(msg *pbgossip.GossipMessage) {
	impl.gossip.Gossip(msg)
}

func (impl *adapterImpl) Accept() <-chan *pbgossip.GossipMessage {
	acceptor := func(message interface{}) bool {
		gossipMessage := message.(*pbgossip.GossipMessage)

		return gossipMessage.Tag == pbgossip.GossipMessage_CHAN_AND_ORG &&
			gossipMessage.GetLeadershipMsg() != nil &&
			bytes.Equal(gossipMessage.Channel, impl.channel)
	}

	gossipMessageCh, _ := impl.gossip.Accept(acceptor, false)

	msgCh := make(chan *pbgossip.GossipMessage)

	go func(inCh <-chan *pbgossip.GossipMessage, outCh chan *pbgossip.GossipMessage, stopCh chan struct{}) {
		for {
			select {
			case <-stopCh:
				return
			case msg, ok := <-inCh:
				if ok {
					outCh <- msg
				} else { // inCh 通道被关闭时，ok 的值会等于 false。
					return
				}
			}
		}
	}(gossipMessageCh, msgCh, impl.stopCh)

	return msgCh
}

func (impl *adapterImpl) CreateMessage(isDeclaration bool) *pbgossip.GossipMessage {
	impl.seqNum++
	seqNum := impl.seqNum

	return &pbgossip.GossipMessage{
		Nonce: 0,
		Tag:   pbgossip.GossipMessage_CHAN_AND_ORG,
		Content: &pbgossip.GossipMessage_LeadershipMsg{
			LeadershipMsg: &pbgossip.LeadershipMessage{
				PkiId:         impl.selfPKIid,
				IsDeclaration: isDeclaration,
				Timestamp: &pbgossip.PeerTime{
					IncNum: impl.incTime,
					SeqNum: seqNum,
				},
			},
		},
		Channel: impl.channel,
	}
}

func (impl *adapterImpl) Peers() []discovery.NetworkMember {
	peers := impl.gossip.PeersOfChannel(impl.channel)

	var res []discovery.NetworkMember
	for _, peer := range peers {
		if impl.gossip.IsInMyOrg(peer) {
			res = append(res, peer)
		}
	}

	return res
}

func (impl *adapterImpl) ReportMetrics(isLeader bool) {
	var leader float64
	if isLeader {
		leader = 1
	}
	impl.metrics.Declaration.With("channel", impl.channel.String()).Set(leader)
}

func (impl *adapterImpl) Stop() {
	select {
	case <-impl.stopCh:
	default:
		close(impl.stopCh)
	}
}
