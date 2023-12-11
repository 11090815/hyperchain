package protoutil

import (
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
	"google.golang.org/protobuf/proto"
)

func UnmarshalSerializedIdentity(raw []byte) (*pbmsp.SerializedIdentity, error) {
	sid := &pbmsp.SerializedIdentity{}
	if err := proto.Unmarshal(raw, sid); err != nil {
		return nil, err
	}
	return sid, nil
}
