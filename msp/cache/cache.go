package cache

import (
	"fmt"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/msp"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
)

var mspLogger = hlogging.MustGetLogger("msp")

const (
	deserializedIdentityCacheSize = 100
	validateIdentityCacheSize     = 100
	satisfiesPrincipalCacheSize   = 100
)

type cachedMSP struct {
	msp.MSP
	deserializedIdentityCache *secondChanceCache
	validateIdentityCache     *secondChanceCache
	satisfiesPrincipalCache   *secondChanceCache
}

type cachedIdentity struct {
	msp.Identity
	cache *cachedMSP
}

func (ci *cachedIdentity) SatisfiesPrincipal(principal *pbmsp.MSPPrincipal) error {
	return ci.cache.SatisfiesPrincipal(ci.Identity, principal)
}

func (ci *cachedIdentity) Validate() error {
	return ci.cache.Validate(ci.Identity)
}

func New(theMsp msp.MSP) (msp.MSP, error) {
	mspLogger.Debugf("Creating cached msp instance.")
	if theMsp == nil {
		return nil, fmt.Errorf("invalid given msp, it should not be nil")
	}

	cMsp := &cachedMSP{MSP: theMsp}
	cMsp.deserializedIdentityCache = newSecondChanceCache(deserializedIdentityCacheSize)
	cMsp.satisfiesPrincipalCache = newSecondChanceCache(satisfiesPrincipalCacheSize)
	cMsp.validateIdentityCache = newSecondChanceCache(validateIdentityCacheSize)

	return cMsp, nil
}

func (cm *cachedMSP) DeserializeIdentity(serializedIdentity []byte) (msp.Identity, error) {
	id, ok := cm.deserializedIdentityCache.get(string(serializedIdentity))
	if ok {
		return &cachedIdentity{
			cache:    cm,
			Identity: id.(msp.Identity),
		}, nil
	}

	id, err := cm.MSP.DeserializeIdentity(serializedIdentity)
	if err == nil {
		cm.deserializedIdentityCache.add(string(serializedIdentity), id)
		return &cachedIdentity{
			cache:    cm,
			Identity: id.(msp.Identity),
		}, nil
	}
	return nil, err
}

func (cm *cachedMSP) Setup(config *pbmsp.MSPConfig) error {
	cm.cleanCache()
	return cm.MSP.Setup(config)
}

func (cm *cachedMSP) Validate(id msp.Identity) error {
	identifier := id.GetIdentifier()
	key := identifier.Mspid + ":" + identifier.Id

	_, ok := cm.validateIdentityCache.get(key)
	if ok {
		return nil
	}

	err := cm.MSP.Validate(id)
	if err == nil {
		cm.validateIdentityCache.add(key, true)
	}
	return err
}

func (cm *cachedMSP) SatisfiesPrincipal(id msp.Identity, principal *pbmsp.MSPPrincipal) error {
	identifier := id.GetIdentifier()
	identityKey := identifier.Mspid + ":" + identifier.Id
	principalKey := principal.PrincipalClassification.String() + string(principal.Principal)
	key := identityKey + principalKey

	v, ok := cm.satisfiesPrincipalCache.get(key)
	if ok {
		if v == nil {
			return nil
		}
		return v.(error)
	}

	err := cm.MSP.SatisfiesPrincipal(id, principal)
	cm.satisfiesPrincipalCache.add(key, err)
	return err
}

func (cm *cachedMSP) cleanCache() {
	cm.deserializedIdentityCache = newSecondChanceCache(deserializedIdentityCacheSize)
	cm.satisfiesPrincipalCache = newSecondChanceCache(satisfiesPrincipalCacheSize)
	cm.validateIdentityCache = newSecondChanceCache(validateIdentityCacheSize)
}
