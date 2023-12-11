package channelconfig

import (
	"time"

	"github.com/11090815/hyperchain/common/configtx"
	"github.com/11090815/hyperchain/common/policies"
	"github.com/11090815/hyperchain/msp"
	pbcommon "github.com/11090815/hyperchain/protos-go/common"
	pborderer "github.com/11090815/hyperchain/protos-go/orderer"
	pbpeer "github.com/11090815/hyperchain/protos-go/peer"
)

// 存储组织的通用配置信息。
type Org interface {
	// 返回该组织的名字
	Name() string

	// 返回与该组织关联的 msp 的 id
	MSPID() string

	// 返回与该组织关联的 msp
	MSP() msp.MSP
}

// 用于存储每个组织的应用配置。
type ApplicationOrg interface {
	Org

	// 返回 gossip 锚点 peer 列表。
	AnchorPeers() []*pbpeer.AnchorPeer
}

// 用于存储每个组织的排序节点的配置。
type OrdererOrg interface {
	Org

	// 返回排序节点的 endpoint。
	Endpoints() []string
}

type Application interface {
	// 组织 id ==> ApplicationOrg
	Organizations() map[string]ApplicationOrg

	// api name ==> policy name
	APIPolicyMapper() PolicyMapper

	// Capabilities 定义了通道应用部分的功能。
	Capabilities() ApplicationCapabilities
}

type Channel interface {
	// 返回计算的哈希值
	HashAlgorithm() func(input []byte) []byte

	// BlockDataHashingStructureWidth 返回构建 merkle 树以计算 BlockData 哈希值时使用的宽度。
	BlockDataHashStructureWidth() uint32

	// OrdererAddresses 返回调用 Broadcast/Deliver 时要连接的有效 orderer 地址列表。
	OrdererAddresses() []string

	// Capabilities 定义了通道的能力。
	Capabilities() ChannelCapabilities
}

// Consortiums 表示由排序服务提供服务的联盟集合。
type Consortiums interface {
	// 返回联盟集合
	Consortiums() map[string]Consortium
}

type Consortium interface {
	// ChannelCreationPolicy 返回为该联盟实例化通道时要检查的策略。
	ChannelCreationPolicy() *pbcommon.Policy

	// Organizations 返回该联盟下的组织。
	Organizations() map[string]Org
}

type Orderer interface {
	// 返回配置的共识类型。
	ConsensusType() string

	// 返回与对应共识类型关联的元数据信息。
	ConsensusMetadata() []byte

	ConsensusState() pborderer.ConsensusType_State

	// BatchSize 返回区块中包含的最大信息数。
	BatchSize() *pborderer.BatchSize

	// BatchTimeout 返回创建批次前需要等待的时间。
	BatchTimeout() time.Duration

	// 返回一个排序网络中允许的最大通道数量。
	MaxChannelsCount() uint64

	Consenters() []*pbcommon.Consenter

	// 返回与排序服务关联的所有组织
	Organizations() map[string]OrdererOrg

	// Capabilities 定义了通道 orderer 部分的功能。
	Capabilities() OrdererCapabilities
}

type PolicyMapper interface {
	// PolicyRefForAPI 获取 API 的名称，并返回策略名称，如果未找到 API，则返回空字符串。
	PolicyRefForAPI(apiName string) string
}

type ApplicationCapabilities interface {
	// 如果该应用中存在所需的未知功能，则 Supported 会返回错误信息。
	Supported() error

	// ForbidDuplicateTXIdInBlock 指定是否允许在同一个区块中出现两个具有相同 TXId 的事务，
	// 或者是否将第二个事务标记为 TxValidationCode_DUPLICATE_TXID。
	ForbidDuplicateTXIdInBlock() bool

	// 如果可以在配置树的应用程序部分指定 ACL，则 ACL 返回 true。
	ACLs() bool

	// 如果启用了对私人通道数据（又称集合）的支持，PrivateChannelData 将返回 true。
	PrivateChannelData() bool

	// 如果此通道已配置为允许通过链码升级更新现有收藏集或添加新收藏集，则 CollectionUpgrade 返回 true。
	CollectionUpgrade() bool

	// V1_1Validation 如果该通道被配置为执行更严格的交易验证（如 v1.1 中所介绍），则返回 true。
	V1_1Validation() bool

	// V1_2Validation 如果该通道被配置为执行更严格的交易验证（如 v1.2 中所介绍），则返回 true。
	V1_2Validation() bool

	// 如果此通道支持 V1.3 版中引入的事务验证，则 V1_3Validation 返回 true。这包括：① 可按分类账密钥粒度
	// 表达的策略，如 FAB-8812 所述；② 新的链码生命周期，如 FAB-11237 所述。
	V1_3Validation() bool

	// 如果 peer 需要存储无效交易的 pvtData，StorePvtDataOfInvalidTx 返回 true（v142 版引入）。
	StorePvtDataOfInvalidTx() bool

	// 如果该通道支持 v2.0 中引入的事务验证，则 V2_0Validation 返回 true。这包括：① 新的链码生命周期；② 每个机构的隐式集合。
	V2_0Validation() bool

	// LifecycleV20 表示对等方应使用已过时且有问题的 v1.x 生命周期，还是使用 v2.0 中引入的较新的按信道批准/提交定义流程。
	// 请注意，这只应在对等处理的认可端使用，这样我们就可以在 v2.1 中安全地移除所有针对它的检查。
	LifecycleV20() bool

	// 该方法总是返回 false。
	MetadataLifecycle() bool

	// 如果该通道支持可按分类账密钥粒度表达的背书策略（如 FAB-8812 所述），KeyLevelEndorsement 将返回 true。
	KeyLevelEndorsement() bool

	// 如果该通道支持清除私人数据条目，则 PurgePvtData 返回 true。
	PurgePvtData() bool
}

type ChannelCapabilities interface {
	// 如果该通道中存在所需的未知功能，则支持返回错误信息
	Supported() error

	MSPVersion() msp.MSPVersion

	// 如果 orderer 和 peer 都允许共识类型迁移，则 ConsensusTypeMigration 返回 true。
	ConsensusTypeMigration() bool

	// 如果通道配置处理允许 orderer 机构指定自己的端点，则 OrgSpecificOrdererEndpoints 返回 true。
	OrgSpecificOrdererEndpoints() bool

	// 如果通道必须支持 BFT 共识，则 ConsensusTypeBFT 返回 true。
	ConsensusTypeBFT() bool
}

type OrdererCapabilities interface {
	// 如果该 orderer 中存在所需的未知功能，则返回错误信息。
	Supported() error

	// PredictableChannelTemplate 用于指定是否要修复 V1.0 版将 /Channel 组的 mod_policy
	// 设置为""并从订购器系统通道配置中复制版本的不良行为。
	PredictableChannelTemplate() bool

	// Resubmission 指定是否应通过重新提交重新验证的 tx 来修复 v1.0 非确定性 tx 承诺。
	Resubmission() bool

	// ExpirationCheck 指定 orderer 在验证报文时是否检查身份过期检查。
	ExpirationCheck() bool

	// ConsensusTypeMigration 检查 orderer 是否允许共识型迁移。
	ConsensusTypeMigration() bool

	// UseChannelCreationPolicyAsAdmins（使用通道创建策略作为管理员策略）检查 orderer 是否
	// 应使用更复杂的通道创建逻辑，如果创建事务似乎支持通道创建策略作为管理员策略的话。
	UseChannelCreationPolicyAsAdmins() bool
}

type Resources interface {
	// 返回通道的 configtx.Validator。
	ConfigtxValidator() configtx.Validator

	// 返回通道的 policies.Manager。
	PolicyManager() policies.Manager

	// 返回链的通道。
	ChannelConfig() Channel

	// 返回通道的 orderer。
	OrdererConfig() (Orderer, bool)

	// 返回通道的联盟。
	ConsortiumsConfig() (Consortiums, bool)

	// 返回通道的应用。
	ApplicationConfig() (Application, bool)

	// 返回链的 msp 管理器。
	MSPManager() msp.MSPManager

	// 如果一组新的配置资源与当前配置资源不兼容，则 ValidateNew 应返回错误。
	ValidateNew(resources Resources) error
}
