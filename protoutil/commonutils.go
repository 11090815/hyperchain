package protoutil

import "google.golang.org/protobuf/proto"

func MarshalOrPanic(pb proto.Message) []byte {
	raw, err := proto.Marshal(pb)
	if err != nil {
		panic(err)
	}
	return raw
}
