package channelconfig

import (
	"fmt"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/msp"
	"github.com/11090815/hyperchain/msp/cache"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
	"google.golang.org/protobuf/proto"
)

type pendingMSPConfig struct {
	mspConfig *pbmsp.MSPConfig
	msp       msp.MSP
}

type MSPConfigHandler struct {
	version msp.MSPVersion
	idMap   map[string]*pendingMSPConfig // msp id ==> *pendingMSPConfig
	csp     bccsp.BCCSP
}

func NewMSPConfigHandler(mspVersion msp.MSPVersion, csp bccsp.BCCSP) *MSPConfigHandler {
	return &MSPConfigHandler{
		version: mspVersion,
		idMap:   make(map[string]*pendingMSPConfig),
		csp:     csp,
	}
}

func (mch *MSPConfigHandler) ProposeMSP(mspConfig *pbmsp.MSPConfig) (msp.MSP, error) {
	var theMSP msp.MSP
	var err error

	inst := msp.New(mch.csp)
	theMSP, err = cache.New(inst)
	if err != nil {
		return nil, fmt.Errorf("failed creating cached msp: [%s]", err.Error())
	}

	if err = theMSP.Setup(mspConfig); err != nil {
		return nil, fmt.Errorf("failed setting up msp: [%s]", err.Error())
	}

	mspID := theMSP.GetIdentifier()
	existed, ok := mch.idMap[mspID]
	if ok && !proto.Equal(existed.mspConfig, mspConfig) {
		return nil, fmt.Errorf("attempted to define two different versions of msp [%s]", mspID)
	}

	// 将新建的 msp 添加到 MSPConfigHandler 里。
	if !ok {
		mch.idMap[mspID] = &pendingMSPConfig{
			mspConfig: mspConfig,
			msp:       theMSP,
		}
	}

	return theMSP, nil
}

func (mch *MSPConfigHandler) CreateMSPManager() (msp.MSPManager, error) {
	mspList := make([]msp.MSP, len(mch.idMap))
	i := 0
	for _, pendingMSP := range mch.idMap {
		mspList[i] = pendingMSP.msp
		i++
	}
	manager := msp.NewMSPManager()
	err := manager.Setup(mspList)
	return manager, err
}
