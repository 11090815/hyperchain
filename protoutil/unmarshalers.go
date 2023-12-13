package protoutil

import (
	pbcommon "github.com/11090815/hyperchain/protos-go/common"
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

func UnmarshalIdentifierHeader(raw []byte) (*pbcommon.IdentifierHeader, error) {
	ih := &pbcommon.IdentifierHeader{}
	if err := proto.Unmarshal(raw, ih); err != nil {
		return nil, err
	}
	return ih, nil
}

func UnmarshalSignatureHeader(raw []byte) (*pbcommon.SignatureHeader, error) {
	sh := &pbcommon.SignatureHeader{}
	if err := proto.Unmarshal(raw, sh); err != nil {
		return nil, err
	}
	return sh, nil
}

func UnmarshalEnvelope(raw []byte) (*pbcommon.Envelope, error) {
	envelope := &pbcommon.Envelope{}
	if err := proto.Unmarshal(raw, envelope); err != nil {
		return nil, err
	}
	return envelope, nil
}

func UnmarshalPayload(raw []byte) (*pbcommon.Payload, error) {
	payload := &pbcommon.Payload{}
	if err := proto.Unmarshal(raw, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func UnmarshalChannelHeader(raw []byte) (*pbcommon.ChannelHeader, error) {
	ch := &pbcommon.ChannelHeader{}
	if err := proto.Unmarshal(raw, ch); err != nil {
		return nil, err
	}
	return ch, nil
}
