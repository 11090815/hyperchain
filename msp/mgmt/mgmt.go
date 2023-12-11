package mgmt

import (
	"sync"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/msp"
)

var (
	mutex     sync.Mutex
	localMSP  msp.MSP
	mspMap    = make(map[string]msp.MSPManager)
	mspLogger = hlogging.MustGetLogger("msp")
)

func GetDeserializers() map[string]msp.IdentityDeserializer {
	mutex.Lock()
	defer mutex.Unlock()

	clone := make(map[string]msp.IdentityDeserializer)

	for key, mspManager := range mspMap {
		clone[key] = mspManager
	}

	return clone
}
