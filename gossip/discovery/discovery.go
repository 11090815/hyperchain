package discovery

import (
	"fmt"

	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/gossip/protoext"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
	"google.golang.org/protobuf/proto"
)

type CryptoService interface {
	// 验证 alive 消息是否被认证
	ValidateAliveMsg(message *protoext.SignedGossipMessage) bool

	// 签署消息
	SignMessage(m *pbgossip.GossipMessage, internalEndpoint string) *pbgossip.Envelope
}

type Discovery interface {
	// 根据提供的 peer 节点的 PKI-ID，搜寻并返回其对应关联的 NetworkMember。
	Lookup(pkiID common.PKIid) *NetworkMember

	// Self 返回该 instance 自身的 NetworkMember。
	Self() NetworkMember

	// UpdateMetadata 更新该 instance 自身的元数据。
	UpdateMetadata([]byte)

	// UpdateExternalEndpoint 更新该 instance 自身的 endpoint。
	UpdateExternalEndpoint(string)

	// Stop 停止该 instance。
	Stop()

	// GetMembership 返回当前 alive 的成员。
	GetMembership() []NetworkMember

	// InitiateSync 向给定数量的 peer 节点发送 GossipMessage_MemReq 消息，询问它们所知道的网络成员信息。
	InitiateSync(int)

	// Connect 使该实例与远程实例连接。identifier 参数是一个函数，可用于
	// 识别对等程序，并断言其 PKI-ID、是否在对等程序的 org 中，以及操作是
	// 否成功。
	Connect(NetworkMember, identifier)
}

// AnchorPeerTracker 是一个传递给 discovery 的接口，用于检查端点是否是锚点 peer。
//
// 在 gossip 协议中，锚点 peer 是指在网络中作为固定参考点的特定节点。它通常是由网络管理员或系统设计者选择并预先配置的节点。
// 锚点 peer 的主要作用是提供网络的可靠性和稳定性。通过设置锚点 peer，可以确保网络中至少存在一些可信赖的节点，它们可以为其他节点提供准确的信息，并确保消息的可靠传递。
type AnchorPeerTracker interface {
	IsAnchorPeer(endpoint string) bool
}

type CommService interface {
	Gossip(msg *protoext.SignedGossipMessage)

	SendToPeer(peer *NetworkMember, msg *protoext.SignedGossipMessage)

	// Ping 向远程节点发送 ping 消息，然后返回一个布尔值表示对方是否回应了 pong。
	Ping(peer *NetworkMember) bool

	// Accept 返回一个 read-only 通道，其中存储着从远程节点那里收到的消息。
	Accept() <-chan protoext.ReceivedMessage

	// 返回一个 read-only 通道，其中存储着那些假定 dead peer。
	PresumedDead() <-chan common.PKIid

	// CloseConn 关闭与给定的节点之间的连接。
	CloseConn(peer *NetworkMember)

	// Forwar 将报文转发至下一跳，但不会将报文转发给最初接收报文的那一跳。
	Forward(msg protoext.SignedGossipMessage)

	// IdentitySwitch 返回一个 read-only 通道，其中存储着那些身份改变的 peer。
	IdentitySwitch() <-chan common.PKIid
}

type EnvelopeFilter func(message *protoext.SignedGossipMessage) *pbgossip.Envelope

// Sieve 是一个筛子，返回的布尔值说明了是否能将报文发送给远程对等点。
type Sieve func(message *protoext.SignedGossipMessage) bool

// DisclosurePolicy 定义了某个远程 peer 有资格了解哪些信息，以及有资格了解某个 SignedGossipMessage 中的哪些信息。
type DisclosurePolicy func(nm *NetworkMember) (Sieve, EnvelopeFilter)

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

// NetworkMember 结构体的作用是表示网络中的成员（peer）的信息。它包含了成员的地址、
// 元数据、PKIid（公钥基础设施标识符）、属性、以及一个Envelope（信封）对象，用于在
// 成员之间传递信息。该结构体用于描述网络中的各个成员，以便进行通信和交互。
type NetworkMember struct {
	Metadata         []byte
	PKIid            common.PKIid
	ExternalEndpoint string // endpoint 一般就是 IP 地址 port 的组合，例如 192.168.111.131:8000
	InternalEndpoint string
	Properties       *pbgossip.Properties
	Envelope         *pbgossip.Envelope
}

func (nm NetworkMember) Clone() NetworkMember {
	pkiID := make(common.PKIid, len(nm.PKIid))
	copy(pkiID, nm.PKIid)
	clone := NetworkMember{
		ExternalEndpoint: nm.ExternalEndpoint,
		Metadata:         nm.Metadata,
		InternalEndpoint: nm.InternalEndpoint,
		PKIid:            pkiID,
	}

	if nm.Envelope != nil {
		clone.Envelope = proto.Clone(nm.Envelope).(*pbgossip.Envelope)
	}

	if nm.Properties != nil {
		clone.Properties = proto.Clone(nm.Properties).(*pbgossip.Properties)
	}

	return clone
}

func (nm NetworkMember) String() string {
	return fmt.Sprintf("NetworkMember{ExternalEndpoint: %s, InternalEndpoint: %s, PKI-ID: %s, Metadata: %x}", nm.ExternalEndpoint, nm.InternalEndpoint, nm.PKIid.String(), nm.Metadata)
}

// PreferredEndpoint 如果peer节点的InternalEndpoint不为空，那么它会优先选择连接到InternalEndpoint而不是标准的Endpoint。这通常与内部网络规则有关。
//
// 内部网络通常是指在同一个网络或子网内的节点之间的通信。这些节点可能位于同一个机房、数据中心或私有云中。在这种情况下，使用内部网络连接可以提供更快的速度、更低的延迟和更高的带宽。
// 相比之下，标准的Endpoint通常是指外部网络或公共互联网上的节点之间的通信。使用公共互联网连接可能会受到网络拥塞、延迟高等因素的影响。
// 因此，peer节点更倾向于使用InternalEndpoint连接，是为了获得更可靠、更高效的网络连接，以提高节点间通信的性能和稳性。
func (nm NetworkMember) PreferredEndpoint() string {
	if nm.InternalEndpoint != "" {
		return nm.InternalEndpoint
	}
	return nm.ExternalEndpoint
}

// HasExternalEndpoint 可以告诉我们给定的 NetworkMember 是否拥有不为空的 external endpoint。
func HasExternalEndpoint(nm NetworkMember) bool {
	return nm.ExternalEndpoint != ""
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type Members []NetworkMember

func (members Members) ByID() map[string]NetworkMember {
	result := make(map[string]NetworkMember)
	for _, nm := range members {
		result[nm.PKIid.String()] = nm
	}
	return result
}

// Intersect 返回两个 Members 的交集。
func (members Members) Intersect(otherMembers Members) Members {
	var result Members
	m := otherMembers.ByID()
	for _, nm := range members {
		if _, exists := m[nm.PKIid.String()]; exists {
			result = append(result, nm)
		}
	}
	return result
}

// Filter 接收一个自定义的过滤器函数：func(nm NetworkMember) bool，经过此过滤器过滤的 NetworkMember 会被留下来，
// 其余的会被忽略掉。
func (members Members) Filter(filter func(nm NetworkMember) bool) Members {
	var result Members
	for _, nm := range members {
		if filter(nm) {
			result = append(result, nm)
		}
	}
	return result
}

// Map 会逐个对 Members 里的对象调用给定的函数：func(NetworkMember) NetworkMember。
func (members Members) Map(f func(NetworkMember) NetworkMember) Members {
	var res Members
	for _, m := range members {
		res = append(res, f(m))
	}
	return res
}

// PeerIdentification 结构体定义了对方 peer 节点的 PKI-ID，并且它其中的
// SelfOrg 字段揭示了该 peer 节点是否与自己在同一组织内。
type PeerIdentification struct {
	ID      common.PKIid
	SelfOrg bool // 对方是否与自己在同一组织内
}

// 用于识别 peer 节点，断言其 PKI-ID，并判断其是否与 identifier 的使用者在同一个 org 内。
type identifier func() (*PeerIdentification, error)
