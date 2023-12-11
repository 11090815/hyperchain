package configtx

import pbcommon "github.com/11090815/hyperchain/protos-go/common"

// Validator 提供了一种机制，用于提出配置更新建议、查看配置更新结果和验证配置更新结果。
type Validator interface {
	// 验证是否尝试应用 configtx 以成为新配置。
	Validate(configEnv *pbcommon.ConfigEnvelope) error

	// 根据当前配置状态验证新的 configtx。
	ProposeConfigUpdate(configtx *pbcommon.Envelope) (*pbcommon.ConfigEnvelope, error)

	// 检索与此管理器关联的通道 ID。
	ChannelID() string

	// ConfigProto 返回当前的配置信息。
	ConfigProto() *pbcommon.Config

	// 返回当前配置的序号。
	Sequence() uint64
}