package api

import "github.com/11090815/hyperchain/gossip/common"

// PeerIdentity 的计算方法如下所示：
//  1. proto.Marshal(pbmsp.SerializedIdentity)
//  2. 将第一步得到的值作为 PeerIdentity。
type PeerIdentity []byte

type MessageCryptoService interface {
	GetPKIidOfCert(peerIdentity PeerIdentity) common.PKIid
}
