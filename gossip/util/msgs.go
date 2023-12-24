package util

import (
	"sync"

	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/gossip/protoext"
)

// MembershipStore 结构体中定义了一个字段：map[string]*protoext.SignedGossipMessage，PKI-ID => *protoext.SignedGossipMessage，
// 用于存储哪个 peer 节点产生了什么 *protoext.SignedGossipMessage。
type MembershipStore struct {
	m     map[string]*protoext.SignedGossipMessage
	mutex *sync.RWMutex
}

func NewMembershipStore() *MembershipStore {
	return &MembershipStore{m: make(map[string]*protoext.SignedGossipMessage), mutex: &sync.RWMutex{}}
}

// MsgByID 根据给定的 PKI-ID，返回 MembershipStore 中存储的 *protoext.SignedGossipMessage。
func (ms *MembershipStore) MsgByID(pkiID common.PKIid) *protoext.SignedGossipMessage {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	if msg, exists := ms.m[pkiID.String()]; exists {
		return msg
	}
	return nil
}

// Size 返回 store 中存储的 PKI-ID 的数量。
func (ms *MembershipStore) Size() int {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	return len(ms.m)
}

func (ms *MembershipStore) Put(pkiID common.PKIid, msg *protoext.SignedGossipMessage) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	ms.m[pkiID.String()] = msg
}

func (ms *MembershipStore) Remove(pkiID common.PKIid) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	delete(ms.m, pkiID.String())
}

func (ms *MembershipStore) ToSlice() []*protoext.SignedGossipMessage {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	msgs := make([]*protoext.SignedGossipMessage, len(ms.m))
	i := 0
	for _, msg := range ms.m {
		msgs[i] = msg
		i++
	}
	return msgs
}
