package identity

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/hyperchain/gossip/api"
	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/vars"
)

var usageThreshold = time.Hour

type Mapper interface {
	Put(pkiID common.PKIid, peerIdentity api.PeerIdentity) error

	Get(pkiID common.PKIid) (api.PeerIdentity, error)

	Sign(msg []byte) ([]byte, error)

	Verify(id, sig, msg []byte) error

	GetPKIidOfCert(api.PeerIdentity) common.PKIid

	SuspectPeers(isSuspected api.PeerSuspector)

	IdentityInfo() api.PeerIdentityInfoSet

	Stop()
}

type purgeTrigger func(pkiID common.PKIid, peerIdentity api.PeerIdentity)

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type identityMapperImpl struct {
	onPurge    purgeTrigger
	mcs        api.MessageCryptoService
	sa         api.SecurityAdvisor
	pkiID2Cert map[string]*storedIdentity
	mutex      *sync.RWMutex
	stopCh     chan struct{}
	once       sync.Once
	selfPKIid  common.PKIid
}

func NewIdentityMapper(mcs api.MessageCryptoService, selfIdentity api.PeerIdentity, onPurge purgeTrigger, sa api.SecurityAdvisor) Mapper {
	selfPKIID := mcs.GetPKIidOfCert(selfIdentity)
	mapper := &identityMapperImpl{
		onPurge:    onPurge,
		mcs:        mcs,
		sa:         sa,
		pkiID2Cert: make(map[string]*storedIdentity),
		mutex:      &sync.RWMutex{},
		stopCh:     make(chan struct{}),
		selfPKIid:  selfPKIID,
	}
	if err := mapper.Put(selfPKIID, selfIdentity); err != nil {
		panic(fmt.Sprintf("failed putting our own identity into the identity mapper, because %s.", err.Error()))
	}
	go mapper.purgeUnusedIdentitiesRoutine()
	return mapper
}

func (imi *identityMapperImpl) Put(pkiID common.PKIid, peerIdentity api.PeerIdentity) error {
	if pkiID == nil {
		return vars.NewPathError("PKIID is nil")
	}

	if peerIdentity == nil {
		return vars.NewPathError("peer identity is nil")
	}

	expirationTime, err := imi.mcs.Expiration(peerIdentity)
	if err != nil {
		return vars.NewPathError(err.Error())
	}

	if err := imi.mcs.ValidateIdentity(peerIdentity); err != nil {
		return vars.NewPathError(err.Error())
	}

	id := imi.mcs.GetPKIidOfCert(peerIdentity)
	if !bytes.Equal(id, pkiID) {
		return vars.NewPathError("identity doesn't match the computed pkiID")
	}

	imi.mutex.Lock()
	defer imi.mutex.Unlock()

	if _, exists := imi.pkiID2Cert[pkiID.String()]; exists {
		return nil
	}

	var expirationTimer *time.Timer
	if !expirationTime.IsZero() {
		if time.Now().After(expirationTime) {
			return vars.NewPathError("peer identity expired")
		}

		timeToLive := time.Until(expirationTime)
		expirationTimer = time.AfterFunc(timeToLive, func() {
			imi.delete(pkiID, peerIdentity)
		})
	}

	imi.pkiID2Cert[pkiID.String()] = newStoredIdentity(pkiID, peerIdentity, expirationTimer, imi.sa.OrgByPeerIdentity(peerIdentity))

	return nil
}

func (imi *identityMapperImpl) Get(pkiID common.PKIid) (api.PeerIdentity, error) {
	imi.mutex.RLock()
	defer imi.mutex.RUnlock()
	identity, exists := imi.pkiID2Cert[pkiID.String()]
	if !exists {
		return nil, vars.NewPathError("PKIID wasn't found")
	}
	return identity.fetchIdentity(), nil
}

func (imi *identityMapperImpl) Sign(msg []byte) ([]byte, error) {
	return imi.mcs.Sign(msg)
}

func (imi *identityMapperImpl) Verify(id, sig, msg []byte) error {
	peerIdentity, err := imi.Get(id)
	if err != nil {
		return vars.NewPathError(err.Error())
	}
	return imi.mcs.Verify(peerIdentity, sig, msg)
}

func (imi *identityMapperImpl) GetPKIidOfCert(peerIdentity api.PeerIdentity) common.PKIid {
	return imi.mcs.GetPKIidOfCert(peerIdentity)
}

func (imi *identityMapperImpl) SuspectPeers(isSuspected api.PeerSuspector) {
	suspectedIdentities := imi.validateIdentities(isSuspected)
	for _, identity := range suspectedIdentities {
		identity.cancelExpirationTimer()
		imi.delete(identity.pkiID, identity.peerIdentity)
		// 将此身份从本 mapper 中删除，并断开与其的连接
	}
}

func (imi *identityMapperImpl) IdentityInfo() api.PeerIdentityInfoSet {
	var result api.PeerIdentityInfoSet
	imi.mutex.RLock()
	defer imi.mutex.RUnlock()

	for _, identity := range imi.pkiID2Cert {
		result = append(result, api.PeerIdentityInfo{
			PKIid:        identity.pkiID,
			Identity:     identity.peerIdentity,
			Organization: identity.organization,
		})
	}

	return result
}

func (imi *identityMapperImpl) Stop() {
	imi.once.Do(func() {
		close(imi.stopCh)
	})
}

func (imi *identityMapperImpl) validateIdentities(isSuspected api.PeerSuspector) []*storedIdentity {
	now := time.Now()
	usageTh := GetIdentityUsageThreshold()

	imi.mutex.RLock()
	defer imi.mutex.RUnlock()

	var revokedIdentities []*storedIdentity
	for pkiID, identity := range imi.pkiID2Cert {
		// 如果该身份是自己，最后一次 fetch 该身份的时间加上使用阈值时间后的结果，如果早于现在当前时间，则该身份会被撤销，
		// 这说明最后一次 fetch 该身份的时间实在太久远了。
		if pkiID != imi.selfPKIid.String() && identity.fetchLastAccessTime().Add(usageTh).Before(now) {
			revokedIdentities = append(revokedIdentities, identity)
			continue
		}
		if !isSuspected(identity.peerIdentity) {
			// 该身份没有被怀疑撤销
			continue
		}
		if err := imi.mcs.ValidateIdentity(identity.fetchIdentity()); err != nil {
			// 此身份验证不通过，则撤销此身份
			revokedIdentities = append(revokedIdentities, identity)
		}
	}

	return revokedIdentities
}

func (imi *identityMapperImpl) delete(pkiID common.PKIid, peerIdentity api.PeerIdentity) {
	imi.mutex.Lock()
	defer imi.mutex.Unlock()
	imi.onPurge(pkiID, peerIdentity) // 关闭与此节点的网络连接
	delete(imi.pkiID2Cert, pkiID.String())
}

func (imi *identityMapperImpl) purgeUnusedIdentitiesRoutine() {
	usageTh := GetIdentityUsageThreshold()
	for {
		select {
		case <-imi.stopCh:
			return
		case <-time.After(usageTh / 10):
			imi.SuspectPeers(func(peerIdentity api.PeerIdentity) bool {
				return false
			})
		}
	}
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type storedIdentity struct {
	pkiID           common.PKIid
	lastAccessTime  int64
	peerIdentity    api.PeerIdentity
	organization    api.OrgIdentity
	expirationTimer *time.Timer // 身份过期后，会从 mapper 中将此身份删除掉
}

func newStoredIdentity(pkiID common.PKIid, peerIdentity api.PeerIdentity, expirationTimer *time.Timer, organization api.OrgIdentity) *storedIdentity {
	return &storedIdentity{
		pkiID:           pkiID,
		peerIdentity:    peerIdentity,
		organization:    organization,
		expirationTimer: expirationTimer,
		lastAccessTime:  time.Now().UnixNano(),
	}
}

func (si *storedIdentity) fetchIdentity() api.PeerIdentity {
	atomic.StoreInt64(&si.lastAccessTime, time.Now().UnixNano())
	return si.peerIdentity
}

func (si *storedIdentity) fetchLastAccessTime() time.Time {
	return time.Unix(0, atomic.LoadInt64(&si.lastAccessTime))
}

func (si *storedIdentity) cancelExpirationTimer() {
	if si.expirationTimer == nil {
		return
	}
	si.expirationTimer.Stop()
}

func GetIdentityUsageThreshold() time.Duration {
	return time.Duration(atomic.LoadInt64((*int64)(&usageThreshold)))
}
