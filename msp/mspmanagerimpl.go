package msp

import (
	"errors"

	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
	"google.golang.org/protobuf/proto"
)

type mspManagerImpl struct {
	mspsMap map[string]MSP
	up      bool
}

func NewMSPManager() MSPManager {
	return &mspManagerImpl{}
}

func (manager *mspManagerImpl) Setup(msps []MSP) error {
	if manager.up {
		mspLogger.Info("MSP manager already up.")
		return nil
	}

	mspLogger.Debugf("Setting up the MSP manager (%d msps).", len(msps))

	manager.mspsMap = make(map[string]MSP)
	for _, msp := range msps {
		manager.mspsMap[msp.GetIdentifier()] = msp
	}

	manager.up = true

	mspLogger.Debugf("MSP manager setup complete, setup %d msps.", len(msps))

	return nil
}

func (manager *mspManagerImpl) GetMSPs() map[string]MSP {
	return manager.mspsMap
}

func (manager *mspManagerImpl) DeserializeIdentity(serializedID []byte) (Identity, error) {
	if !manager.up {
		return nil, errors.New("msp manager is not up")
	}

	sid := &pbmsp.SerializedIdentity{}
	if err := proto.Unmarshal(serializedID, sid); err != nil {
		return nil, err
	}

	msp := manager.mspsMap[sid.Mspid]
	return msp.(*bccspmsp).deserializeIdentityInternal(sid.IdBytes)
}

func (manager *mspManagerImpl) IsWellFormed(identity *pbmsp.SerializedIdentity) error {
	for _, msp := range manager.mspsMap {
		if err := msp.IsWellFormed(identity); err == nil {
			return nil
		}
	}
	return errors.New("no msp provider recognizes the identity")
}
