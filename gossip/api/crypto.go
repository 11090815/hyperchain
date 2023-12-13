package api

import (
	"time"

	"github.com/11090815/hyperchain/gossip/common"
	pbcommon "github.com/11090815/hyperchain/protos-go/common"
)

// PeerIdentity 的计算方法如下所示：
//  1. proto.Marshal(pbmsp.SerializedIdentity)
//  2. 将第一步得到的值作为 PeerIdentity。
type PeerIdentity []byte

type MessageCryptoService interface {
	GetPKIidOfCert(peerIdentity PeerIdentity) common.PKIid

	VerifyBlock(channelID common.ChannelID, seqNum uint64, block *pbcommon.Block) error

	VerifyBlockAttestation(channelID string, block *pbcommon.Block) error

	Sign(message []byte) ([]byte, error)

	Verify(peerIdentity PeerIdentity, signature, message []byte) error

	VerifyByChannel(channelID common.ChannelID, peerIdentity PeerIdentity, signature, message []byte) error

	ValidateIdentity(peerIdentity PeerIdentity) error

	Expiration(peerIdentity PeerIdentity) (time.Time, error)
}
