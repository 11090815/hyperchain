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

type OrgIdentity []byte

type PeerIdentityInfo struct {
	PKIid        common.PKIid
	Identity     PeerIdentity
	Organization OrgIdentity
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type PeerIdentityInfoSet []PeerIdentityInfo

// PeerIdentityFilter 能被过滤出来的（返回值是 true）是需要被留下的，不能被过滤出来的都被舍弃了。
type PeerIdentityFilter func(info PeerIdentityInfo) bool

// ByOrg 整理 PeerIdentityInfoSet，得到：map<Organization, PeerIdentityInfoSet>，
// 之所以 map 的 value 是 PeerIdentityInfoSet，是因为同一个组织下可能有多个 peer。
func (piis PeerIdentityInfoSet) ByOrg() map[string]PeerIdentityInfoSet {
	result := make(map[string]PeerIdentityInfoSet)
	for _, info := range piis {
		result[string(info.Organization)] = append(result[string(info.Organization)], info)
	}

	return result
}

// ByID 整理 PeerIdentityInfoSet，得到：map<PKIid, PeerIdentityInfo>，PKIid 对应唯一的 peer。
func (piis PeerIdentityInfoSet) ByID() map[string]PeerIdentityInfo {
	result := make(map[string]PeerIdentityInfo)
	for _, info := range piis {
		result[string(info.PKIid)] = info
	}

	return result
}

func (piis PeerIdentityInfoSet) Filter(filter PeerIdentityFilter) PeerIdentityInfoSet {
	var result PeerIdentityInfoSet
	for _, id := range piis {
		if filter(id) {
			result = append(result, id)
		}
	}
	return result
}

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

// PeerSuspector 返回具有给定身份的 peer 是否被怀疑已被撤销，或其 CA 是否已被撤销。
type PeerSuspector func(peerIdentity PeerIdentity) bool
