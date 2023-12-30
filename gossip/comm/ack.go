package comm

import (
	"github.com/11090815/hyperchain/gossip/discovery"
	"github.com/11090815/hyperchain/gossip/protoext"
)

type (
	sendFunc func(peer *discovery.NetworkMember, msg *protoext.SignedGossipMessage)
)
