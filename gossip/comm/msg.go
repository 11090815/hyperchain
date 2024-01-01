package comm

import (
	"github.com/11090815/hyperchain/gossip/protoext"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
)

type ReceivedMessageImpl struct {
	signedGossipMessage *protoext.SignedGossipMessage
	conn                *connection
	connInfo            *protoext.ConnectionInfo
}

func (rmi *ReceivedMessageImpl) GetEnvelope() *pbgossip.Envelope {
	return rmi.signedGossipMessage.Envelope
}

func (rmi *ReceivedMessageImpl) GetSignedGossipMessage() *protoext.SignedGossipMessage {
	return rmi.signedGossipMessage
}

func (rmi *ReceivedMessageImpl) GetConnectionInfo() *protoext.ConnectionInfo {
	return rmi.connInfo
}

func (rmi *ReceivedMessageImpl) Respond(msg *pbgossip.GossipMessage) {
	signedMsg, _ := protoext.NoopSign(msg)
	rmi.conn.send(signedMsg, func(error) {}, true)
}

func (rmi *ReceivedMessageImpl) Ack(err error) {
	ackMsg := &pbgossip.GossipMessage{
		Nonce: rmi.signedGossipMessage.GossipMessage.Nonce,
		Content: &pbgossip.GossipMessage_Ack{
			Ack: &pbgossip.Acknowledgement{
				Error: err.Error(),
			},
		},
	}

	rmi.Respond(ackMsg)
}
