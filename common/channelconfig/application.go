package channelconfig

import (
	pbcommon "github.com/11090815/hyperchain/protos-go/common"
	pbpeer "github.com/11090815/hyperchain/protos-go/peer"
)

type ApplicationProtos struct {
	ACLs         *pbpeer.ACLs
	Capabilities *pbcommon.Capabilities
}

type ApplicationConfig struct {
	applicationOrgs map[string]ApplicationOrg
	protos          *ApplicationProtos
}
