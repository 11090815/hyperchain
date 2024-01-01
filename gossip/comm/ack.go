package comm

import (
	"encoding/json"
	"fmt"

	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/gossip/discovery"
	"github.com/11090815/hyperchain/gossip/protoext"
	"github.com/11090815/hyperchain/gossip/util"
)

type (
	sendFunc func(peer *discovery.NetworkMember, msg *protoext.SignedGossipMessage)
	waitFunc func(*discovery.NetworkMember) error
)

type ackSendOpration struct {
	snd        sendFunc
	waitForAck waitFunc
}

type SendResult struct {
	error
	discovery.NetworkMember
}

type SendResults []SendResult

func (srs SendResults) AckCount() int {
	c := 0
	for _, ack := range srs {
		if ack.error == nil {
			c++
		}
	}
	return c
}

func (srs SendResults) NackCount() int {
	return len(srs) - srs.AckCount()
}

func (srs SendResults) String() string {
	errMap := map[string]int{}
	for _, ack := range srs {
		if ack.error == nil {
			continue
		}
		errMap[ack.Error()]++
	}

	ackCount := srs.AckCount()
	output := map[string]interface{}{}

	output["successes"] = ackCount
	output["failures"] = errMap

	bz, _ := json.Marshal(output)
	return string(bz)
}

func (aso *ackSendOpration) send(msg *protoext.SignedGossipMessage, minAckNum int, peers ...*discovery.NetworkMember) SendResults {
	successAcks := 0
	results := []SendResult{}

	acks := make(chan SendResult, len(peers))
	for _, p := range peers {
		go func(p *discovery.NetworkMember) {
			aso.snd(p, msg)
			err := aso.waitForAck(p)
			acks <- SendResult{
				error:         err,
				NetworkMember: *p,
			}
		}(p)
	}
	for {
		ack := <-acks
		results = append(results, SendResult{
			error:         ack.error,
			NetworkMember: ack.NetworkMember,
		})
		if ack.error == nil {
			successAcks++
		}
		if successAcks == minAckNum || len(results) == len(peers) {
			break
		}
	}

	return results
}

func interceptAcks(nextHandler handler, remotePeerID common.PKIid, pubsub *util.PubSub) handler {
	return func(message *protoext.SignedGossipMessage) {
		if message.GossipMessage.GetAck() != nil {
			topic := topicForAck(message.GossipMessage.Nonce, remotePeerID)
			pubsub.Publish(topic, message.GossipMessage.GetAck())
			return
		}
		nextHandler(message)
	}
}

func topicForAck(nonce uint64, pkiID common.PKIid) string {
	return fmt.Sprintf("%d@%s", nonce, pkiID.String())
}
