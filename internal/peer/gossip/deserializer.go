package gossip

import (
	"github.com/11090815/hyperchain/msp"
	"github.com/11090815/hyperchain/msp/mgmt"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
	"github.com/11090815/hyperchain/protoutil"
)

type DeserializersManager interface {
	// 接收 proto.Marshal(pbmsp.SerializedIdentity) 字节切片 raw，对 raw 进行反序列化，
	// 得到 pbmsp.SerializedIdentity。
	Deserialize(raw []byte) (*pbmsp.SerializedIdentity, error)

	// 返回本地 msp 的标识符。
	GetLocalMSPIdentifier() string

	// 返回本地身份反序列化器 msp.IdentityDeserializer。
	GetLocalDeserializer() msp.IdentityDeserializer

	// 返回一个映射：通道 id ==> 通道反序列化器
	GetChannelDeserializers() map[string]msp.IdentityDeserializer
}

type mspDeserializerManager struct {
	localMSP msp.MSP
}

func NewDeserializersManager(localMSP msp.MSP) DeserializersManager {
	return &mspDeserializerManager{localMSP: localMSP}
}

func (m *mspDeserializerManager) Deserialize(raw []byte) (*pbmsp.SerializedIdentity, error) {
	return protoutil.UnmarshalSerializedIdentity(raw)
}

func (m *mspDeserializerManager) GetLocalMSPIdentifier() string {
	return m.localMSP.GetIdentifier()
}

func (m *mspDeserializerManager) GetLocalDeserializer() msp.IdentityDeserializer {
	return m.localMSP
}

func (m *mspDeserializerManager) GetChannelDeserializers() map[string]msp.IdentityDeserializer {
	return mgmt.GetDeserializers()
}
