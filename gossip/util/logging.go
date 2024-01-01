package util

import (
	"fmt"
	"sync"

	"github.com/11090815/hyperchain/common/hlogging"
)

const (
	DiscoveryLogger = "gossip.discovery"
	ElectionLogger  = "gossip.election"
	CommLogger      = "gossip.comm"
)

var (
	loggers = make(map[string]*hlogging.HyperchainLogger)
	mutex   = &sync.Mutex{}
)

func GetLogger(model string, endpoint string) *hlogging.HyperchainLogger {
	var loggerName string
	if endpoint == "" {
		loggerName = model
	} else {
		loggerName = fmt.Sprintf("%s@%s", endpoint, model)
	}

	mutex.Lock()
	defer mutex.Unlock()

	if logger, ok := loggers[loggerName]; ok {
		return logger
	}

	logger := hlogging.MustGetLogger(loggerName)
	loggers[loggerName] = logger

	return logger
}
