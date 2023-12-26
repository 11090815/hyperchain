package discovery

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/gossip/gossip/msgstore"
	"github.com/11090815/hyperchain/gossip/protoext"
	"github.com/11090815/hyperchain/gossip/util"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
	"github.com/11090815/hyperchain/vars"
)

const (
	DefaultAliveTimeInterval            = 5 * time.Second
	DefaultAliveExpirationTimeout       = 5 * DefaultAliveTimeInterval
	DefaultAliveExpirationCheckInterval = DefaultAliveExpirationTimeout / 10
	DefaultReconnectInterval            = DefaultAliveExpirationTimeout
	DefaultMsgExpirationFactor          = 20
	DefaultMaxConnectionAttempts        = 120
)

type timestamp struct {
	incTime  time.Time
	seqNum   uint64
	lastSeen time.Time
}

func (ts *timestamp) String() string {
	if !ts.lastSeen.IsZero() {
		return fmt.Sprintf("timestamp{incTime: %d, seqNum: %d, lastSeen: %s}", ts.incTime.UnixNano(), ts.seqNum, ts.lastSeen.Format(time.RFC3339))
	}
	return fmt.Sprintf("timestamp{incTime: %d, seqNum: %d}", ts.incTime.UnixNano(), ts.seqNum)
}

type aliveMsgStore struct {
	msgstore.MessageStore
}

func newAliveMsgStore(impl *gossipDiscoveryImpl) *aliveMsgStore {
	policy := protoext.NewGossipMessageComparator(0)
	trigger := func(m interface{}) {}
	aliveMsgTTL := impl.config.AliveExpirationTimeout * time.Duration(impl.config.MsgExpirationFactor)
	externalLock := func() { impl.mutex.Lock() }
	externalUnlock := func() { impl.mutex.Unlock() }
	expireCallback := func(m interface{}) {
		signedGossipMessage := m.(*protoext.SignedGossipMessage)
		if signedGossipMessage.GossipMessage.GetAliveMsg() == nil {
			return
		}

		membership := signedGossipMessage.GossipMessage.GetAliveMsg().Membership
		pkiIDStr := hex.EncodeToString(membership.PkiId)
		endpoint := membership.Endpoint
		internalEndpoint := protoext.InternalEndpoint(signedGossipMessage.Envelope.SecretEnvelope)

		if util.Contains(endpoint, impl.config.BootstrapPeers) || util.Contains(internalEndpoint, impl.config.BootstrapPeers) ||
			impl.anchorPeerTracker.IsAnchorPeer(endpoint) || impl.anchorPeerTracker.IsAnchorPeer(internalEndpoint) {
			// 锚点 peer 不能删除
			impl.logger.Debugf("Don't remove bootstrap or anchor peer endpoint %s from membership.", endpoint)
			return
		}

		impl.logger.Infof("Removing member, whose endpoint is \"%s\" and internal endpoint is \"%s\" and pki-id is \"%s\".", endpoint, internalEndpoint, pkiIDStr)
		impl.aliveMembership.Remove(membership.PkiId)
		impl.deadMembership.Remove(membership.PkiId)
		delete(impl.aliveLastTS, pkiIDStr)
		delete(impl.deadLastTS, pkiIDStr)
		delete(impl.id2Member, pkiIDStr)
	}

	store := &aliveMsgStore{
		MessageStore: msgstore.NewMessageStoreExpirable(policy, trigger, aliveMsgTTL, externalLock, externalUnlock, expireCallback),
	}
	return store
}

type DiscoveryConfig struct {
	AliveTimeInterval            time.Duration // 用于发送 alive 消息的时间间隔
	AliveExpirationTimeout       time.Duration // alive 消息的过期时间
	AliveExpirationCheckInterval time.Duration // 检查 alive 消息是否过期的时间间隔
	ReconnectInterval            time.Duration // 重连的时间间隔
	MaxConnectionAttempts        int           // 最大连接尝试次数
	MsgExpirationFactor          int           // 消息过期时间的因子
	BootstrapPeers               []string      // 用于引导的节点 endpoint 列表
}

type gossipDiscoveryImpl struct {
	incTime          uint64
	seqNum           uint64
	self             NetworkMember                 // 表示当前节点自身的网络成员信息。
	selfAliveMessage *protoext.SignedGossipMessage // 每隔 AliveTimeInterval 这么长时间，我会更新一次 selfAliveMessage
	id2Member        map[string]*NetworkMember     // 用于存储已知节点的ID和对应的NetworkMember结构体。
	port             int
	cryptoService    CryptoService
	commService      CommService
	stopCh           chan struct{}
	stopOnce         sync.Once
	logger           *hlogging.HyperchainLogger
	config           DiscoveryConfig
	pubsub           *util.PubSub
	aliveMsgStore    *aliveMsgStore // 里面不会存储自己的 alive 消息

	disclosurePolicy DisclosurePolicy

	// 每次收到节点的 alive 消息都会更新一下 aliveMembership 和 aliveLastTS。
	aliveMembership *util.MembershipStore
	// aliveLastTS 与 deadLastTS 两个字段是互斥的，也就是说，某个节点存在于 aliveLastTS 里的话，就一定不会存在于 deadLastTS 里。
	aliveLastTS map[string]*timestamp // PKI-ID => *timestamp

	deadMembership *util.MembershipStore
	// deadLastTS 与 aliveLastTS 两个字段是互斥的，也就是说，某个节点存在于 deadLastTS 里的话，就一定不会存在于 aliveLastTS 里。
	deadLastTS map[string]*timestamp // PKI-ID => *timestamp

	anchorPeerTracker AnchorPeerTracker

	mutex *sync.RWMutex
}

func NewDiscoveryService(self NetworkMember, commService CommService, cryptoService CryptoService, disclosurePolicy DisclosurePolicy, config DiscoveryConfig, anchorPeerTracker AnchorPeerTracker, logger *hlogging.HyperchainLogger) Discovery {
	impl := &gossipDiscoveryImpl{
		incTime:           uint64(time.Now().UnixNano()),
		seqNum:            uint64(0),
		self:              self,
		id2Member:         make(map[string]*NetworkMember),
		cryptoService:     cryptoService,
		commService:       commService,
		stopCh:            make(chan struct{}),
		logger:            logger,
		config:            config,
		pubsub:            util.NewPubSub(),
		disclosurePolicy:  disclosurePolicy,
		aliveMembership:   util.NewMembershipStore(),
		aliveLastTS:       make(map[string]*timestamp),
		deadMembership:    util.NewMembershipStore(),
		deadLastTS:        make(map[string]*timestamp),
		anchorPeerTracker: anchorPeerTracker,
		mutex:             &sync.RWMutex{},
	}

	impl.validateSelf()
	impl.aliveMsgStore = newAliveMsgStore(impl)

	go impl.sendAliveMessageRoutine()
	go impl.checkAliveRoutine()
	go impl.handleMessagesRoutine()
	go impl.reconnectToDeadRoutine()
	go impl.handleEventsRoutine()

	return impl
}

func (impl *gossipDiscoveryImpl) Lookup(pkiID common.PKIid) *NetworkMember {
	if bytes.Equal(pkiID, impl.self.PKIid) {
		return &impl.self
	}
	impl.mutex.RLock()
	defer impl.mutex.RUnlock()
	return copyNetworkMember(impl.id2Member[pkiID.String()])
}

func (impl *gossipDiscoveryImpl) Self() NetworkMember {
	var envelope *pbgossip.Envelope
	msg, _ := impl.aliveMsgAndInternalEndpoint()
	signedMsg, _ := protoext.NoopSign(msg)
	envelope = signedMsg.Envelope
	membership := msg.GetAliveMsg().Membership

	return NetworkMember{
		Metadata:         membership.Metadata,
		ExternalEndpoint: membership.Endpoint,
		PKIid:            membership.PkiId,
		Envelope:         envelope,
	}
}

func (impl *gossipDiscoveryImpl) UpdateMetadata(data []byte) {
	impl.mutex.Lock()
	impl.self.Metadata = data
	impl.mutex.Unlock()
}

func (impl *gossipDiscoveryImpl) UpdateExternalEndpoint(endpoint string) {
	impl.mutex.Lock()
	impl.self.ExternalEndpoint = endpoint
	impl.mutex.Unlock()
}

func (impl *gossipDiscoveryImpl) Stop() {
	impl.stopOnce.Do(func() {
		close(impl.stopCh)
		impl.aliveMsgStore.Stop()
		impl.logger.Info("Stop gossip discovery service.")
	})
}

func (impl *gossipDiscoveryImpl) GetMembership() []NetworkMember {
	if impl.stopped() {
		return []NetworkMember{}
	}
	impl.mutex.RLock()
	defer impl.mutex.RUnlock()

	result := []NetworkMember{}
	for _, member := range impl.aliveMembership.ToSlice() {
		aliveMsg := member.GossipMessage.GetAliveMsg()
		result = append(result, NetworkMember{
			PKIid:            aliveMsg.Membership.PkiId,
			ExternalEndpoint: aliveMsg.Membership.Endpoint,
			Metadata:         aliveMsg.Membership.Metadata,
			InternalEndpoint: impl.id2Member[hex.EncodeToString(aliveMsg.Membership.PkiId)].InternalEndpoint,
			Envelope:         member.Envelope,
		})
	}

	return result
}

func (impl *gossipDiscoveryImpl) InitiateSync(peerNum int) {
	if impl.stopped() {
		return
	}

	var peers2SendTo []*NetworkMember

	impl.mutex.RLock()
	n := impl.aliveMembership.Size()

	k := peerNum
	if k > n {
		k = n
	}
	aliveMemberArray := impl.aliveMembership.ToSlice()
	for _, i := range util.GetRandomIndices(k, n-1) {
		// 从 n 个活跃的节点中随机挑选 k 个
		pulledPeer := aliveMemberArray[i].GossipMessage.GetAliveMsg().Membership
		var internalEndpoint string
		if aliveMemberArray[i].Envelope.SecretEnvelope != nil {
			internalEndpoint = protoext.InternalEndpoint(aliveMemberArray[i].Envelope.SecretEnvelope)
		}
		netMember := &NetworkMember{
			ExternalEndpoint: pulledPeer.Endpoint,
			Metadata:         pulledPeer.Metadata,
			PKIid:            pulledPeer.PkiId,
			InternalEndpoint: internalEndpoint,
		}
		peers2SendTo = append(peers2SendTo, netMember)
	}
	impl.mutex.RUnlock()

	if len(peers2SendTo) == 0 {
		impl.logger.Debug("No peers to send to, abort membership sync.")
		return
	}

	req, err := impl.createMembershipRequest(true)
	if err != nil {
		impl.logger.Warnf("Failed creating membership request, because %s.", err.Error())
		return
	}
	signedReq, _ := protoext.NoopSign(req)

	for _, peer := range peers2SendTo {
		impl.commService.SendToPeer(peer, signedReq)
	}
}

func (impl *gossipDiscoveryImpl) Connect(member NetworkMember, id identifier) {
	for _, endpoint := range []string{member.InternalEndpoint, member.ExternalEndpoint} {
		if impl.isMyOwnEndpoint(endpoint) {
			impl.logger.Debug("Skipping connecting to myself.")
			return
		}
	}

	go func() {
		for i := 0; i < impl.config.MaxConnectionAttempts; i++ {
			id, err := id()
			if err != nil {
				if impl.stopped() {
					return
				}
				impl.logger.Warnf("Could not connect to %s, because %s.", member.String(), err.Error())
				time.Sleep(impl.config.ReconnectInterval)
				continue
			}

			peer := &NetworkMember{
				InternalEndpoint: member.InternalEndpoint,
				ExternalEndpoint: member.ExternalEndpoint,
				PKIid:            id.PKIid,
			}

			req, err := impl.createMembershipRequest(id.SelfOrg)
			if err != nil {
				impl.logger.Warnf("Failed creating membership request, because %s.", err.Error())
				continue
			}

			signedReq, _ := protoext.NoopSign(req)

			go impl.sendUntilAcked(peer, signedReq)
			return
		}
	}()
}

func (impl *gossipDiscoveryImpl) isMyOwnEndpoint(endpoint string) bool {
	return endpoint == fmt.Sprintf("127.0.0.1:%d", impl.port) ||
		endpoint == fmt.Sprintf("localhost:%d", impl.port) ||
		endpoint == impl.self.InternalEndpoint ||
		endpoint == impl.self.ExternalEndpoint
}

func (impl *gossipDiscoveryImpl) getMySignedAliveMessage(includeInternalEndpoint bool) (*protoext.SignedGossipMessage, error) {
	aliveMsg, internalEndpoint := impl.aliveMsgAndInternalEndpoint()
	envelope := impl.cryptoService.SignMessage(aliveMsg, internalEndpoint)
	if envelope == nil {
		return nil, vars.NewPathError("failed signing alive message")
	}

	signedGossipMessage := &protoext.SignedGossipMessage{
		GossipMessage: aliveMsg,
		Envelope:      envelope,
	}

	// 当 includeInternalEndpoint 为 false 时，意味着不包含内部端点信息。SecretEnvelope 字段用于存储加密的内部端点信息。
	// 如果不需要包含内部端点信息，将 SecretEnvelope 置为空可以避免传输不必要的数据。这样做有以下几个原因：
	//	1. 数据保护：内部端点信息可能包含敏感的网络拓扑或身份验证信息。将其置为空可以防止不必要的泄露和数据暴露。
	//	2. 数据大小：包含内部端点信息会增加消息的大小。在一些情况下，消息大小的限制可能会成为问题。通过将 SecretEnvelope 置为空，可以减小消息的大小，减少网络传输的负载。
	//	3. 隐私保护：如果不需要内部端点信息，将其置为空可以提高节点的隐私护。通过减少传输的敏感信息，可以降低受到攻击的风险。
	//
	// 如果消息的接收方与自己在同一组织内，那么，我们就可以将 SecretEnvelope 信息发送过去。
	if !includeInternalEndpoint {
		signedGossipMessage.Envelope.SecretEnvelope = nil
	}

	return signedGossipMessage, nil
}

// aliveMsgAndInternalEndpoint 用于创建一个Gossip消息，并且在该消息中包含了当前成员的信息以及时间戳。
func (impl *gossipDiscoveryImpl) aliveMsgAndInternalEndpoint() (*pbgossip.GossipMessage, string) {
	impl.mutex.Lock()
	defer impl.mutex.Unlock()
	impl.seqNum++

	msg := &pbgossip.GossipMessage{
		Tag: pbgossip.GossipMessage_EMPTY,
		Content: &pbgossip.GossipMessage_AliveMsg{
			AliveMsg: &pbgossip.AliveMessage{
				Membership: &pbgossip.Membership{
					Endpoint: impl.self.ExternalEndpoint,
					Metadata: impl.self.Metadata,
					PkiId:    impl.self.PKIid,
				},
				Timestamp: &pbgossip.PeerTime{
					IncNum: impl.incTime,
					SeqNum: impl.seqNum,
				},
			},
		},
	}
	return msg, impl.self.InternalEndpoint
}

func (impl *gossipDiscoveryImpl) createMembershipResponse(me *protoext.SignedGossipMessage, targetPeer *NetworkMember) *pbgossip.MembershipResponse {
	// shouldBeDisclosed：告诉我们哪些 member 可以告诉 targetPeer；
	// omitConcealedFields：告诉我们对于什么样的 targetPeer，我们可以将 member 的 SecretEnvelope 告诉它。
	shouldBeDisclosed, omitConcealedFields := impl.disclosurePolicy(targetPeer)

	if !shouldBeDisclosed(me) {
		// 我不应该把我所知道的 membership 披露给 targetPeer。
		// 对于以下几种情况，我们不应该把所知道的 membership 披露给 targetPeer：
		//	1. targetPeer 的组织不明；
		//	2. 我所在的组织不明；
		//	3. 我与 targetPeer 不在同一个组织内；
		//	4. 我与 targetPeer 不属于统一组织且我的 ExternalEndpoint 不明时，或者 targetPeer 的 ExternalEndpoint 不明时。
		return nil
	}

	impl.mutex.RLock()
	defer impl.mutex.RUnlock()

	deadPeers := []*pbgossip.Envelope{}
	for _, deadMember := range impl.deadMembership.ToSlice() {
		if !shouldBeDisclosed(deadMember) {
			// 对于以下几种情况，我们不应该把这个 deadMember 告诉 targetPeer：
			//	1. targetPeer 的组织不明；
			//	2. deadMember 的组织不明；
			//	3. deadMember 与 targetPeer 既不属于统一组织，我与 deadMember 也不属于统一组织；
			//	4. deadMember 与 targetPeer 不属于统一组织且 deadMember 的 ExternalEndpoint 不明时，或者 targetPeer 的 ExternalEndpoint 不明时。
			continue
		}
		// 如果 targetPeer 与我不在同一个组织内，那么我们不会将 deadMember 的 SecretEnvelope 告诉 targetPeer，
		// SecretEnvelope 里存储的是 deadMember 的 InternalEndpoint。
		deadPeers = append(deadPeers, omitConcealedFields(deadMember))
	}

	alivePeers := []*pbgossip.Envelope{}
	for _, aliveMember := range impl.aliveMembership.ToSlice() {
		if !shouldBeDisclosed(aliveMember) {
			// 对于以下几种情况，我们不应该把这个 aliveMember 告诉 targetPeer：
			//	1. targetPeer 的组织不明；
			//	2. aliveMember 的组织不明；
			//	3. aliveMember 与 targetPeer 既不属于统一组织，且我与 aliveMember 也不属于统一组织；
			//	4. aliveMember 与 targetPeer 不属于统一组织且 aliveMember 的 ExternalEndpoint 不明时，或者 targetPeer 的 ExternalEndpoint 不明时。
			continue
		}
		// 如果 targetPeer 与我不在同一个组织内，那么我们不会将 aliveMember 的 SecretEnvelope 告诉 targetPeer，
		// SecretEnvelope 里存储的是 aliveMember 的 InternalEndpoint。
		alivePeers = append(alivePeers, omitConcealedFields(aliveMember))
	}

	return &pbgossip.MembershipResponse{
		Alive:    append(alivePeers, omitConcealedFields(me)),
		Dead:     deadPeers,
		PkiId:    impl.self.PKIid,
		Endpoint: impl.self.ExternalEndpoint,
	}
}

func (impl *gossipDiscoveryImpl) createMembershipRequest(includeInternalEndpoint bool) (*pbgossip.GossipMessage, error) {
	signedAliveMessage, err := impl.getMySignedAliveMessage(includeInternalEndpoint)
	if err != nil {
		return nil, vars.NewPathError(err.Error())
	}

	req := &pbgossip.MembershipRequest{
		SelfInformation: signedAliveMessage.Envelope,
		Known:           [][]byte{},
	}

	return &pbgossip.GossipMessage{
		Tag:   pbgossip.GossipMessage_EMPTY,
		Nonce: util.RandomUint64(),
		Content: &pbgossip.GossipMessage_MemReq{
			MemReq: req,
		},
	}, nil
}

// stopped 判断 discovery 服务是否被关闭了。
func (impl *gossipDiscoveryImpl) stopped() bool {
	select {
	case <-impl.stopCh:
		return true
	default:
		return false
	}
}

func (impl *gossipDiscoveryImpl) sendUntilAcked(peer *NetworkMember, message *protoext.SignedGossipMessage) {
	nonce := message.GossipMessage.Nonce
	for i := 0; i < impl.config.MaxConnectionAttempts && !impl.stopped(); i++ {
		sub := impl.pubsub.Subscribe(fmt.Sprintf("%d", nonce), time.Second*5)
		impl.commService.SendToPeer(peer, message)
		if _, timeoutErr := sub.Listen(); timeoutErr == nil {
			// 我最好能在重连时间超时之前收到对方的回应！
			return
		}
		time.Sleep(impl.config.ReconnectInterval)
	}
}

// getDeadMembers 统计出来有哪些节点已经很长时间没有给我发送 alive 消息了，我们判定
// 这些节点已经 dead 了。
func (impl *gossipDiscoveryImpl) getDeadMembers() []common.PKIid {
	impl.mutex.RLock()
	defer impl.mutex.RUnlock()

	dead := []common.PKIid{}
	for id, last := range impl.aliveLastTS {
		// 计算有多长时间没收到它的 alive 消息了
		elapsedNonAliveTime := time.Since(last.lastSeen)
		if elapsedNonAliveTime > impl.config.AliveExpirationTimeout {
			impl.logger.Warnf("Haven't heard from %s for %vs.", id, elapsedNonAliveTime.Seconds())
			dead = append(dead, common.StrToPKIid(id))
		}
	}

	return dead
}

func (impl *gossipDiscoveryImpl) addDeadMembersAndRemoveThemFromAliveMap(dead []common.PKIid) {
	impl.mutex.Lock()
	for _, pkiID := range dead {
		if _, exists := impl.aliveLastTS[pkiID.String()]; !exists {
			// 不存在，即该节点已经 dead
			continue
		}
		go func(id common.PKIid) {
			defer func() {
				impl.logger.Debugf("Closing connection to %s.", pkiID.String())
			}()
			impl.commService.CloseConn(impl.id2Member[pkiID.String()])
		}(pkiID)

		impl.deadLastTS[pkiID.String()] = impl.aliveLastTS[pkiID.String()]
		delete(impl.aliveLastTS, pkiID.String())
		if aliveMsg := impl.aliveMembership.MsgByID(pkiID); aliveMsg != nil {
			impl.deadMembership.Put(pkiID, aliveMsg)
			impl.aliveMembership.Remove(pkiID)
		}
	}
	impl.mutex.Unlock()
}

func (impl *gossipDiscoveryImpl) learnNewMembers(aliveMembers []*protoext.SignedGossipMessage, deadMembers []*protoext.SignedGossipMessage) {
	impl.mutex.Lock()
	defer impl.mutex.Unlock()

	for _, am := range aliveMembers {
		receivedPKIID := am.GossipMessage.GetAliveMsg().Membership.PkiId
		if bytes.Equal(receivedPKIID, impl.self.PKIid) {
			continue
		}
		now := time.Now()
		impl.aliveLastTS[hex.EncodeToString(receivedPKIID)] = &timestamp{
			incTime:  tsToTime(am.GossipMessage.GetAliveMsg().Timestamp.IncNum),
			lastSeen: now,
			seqNum:   am.GossipMessage.GetAliveMsg().Timestamp.SeqNum,
		}
		impl.logger.Debugf("Last seen alive member %s at %s.", hex.EncodeToString(receivedPKIID), now.Format(time.RFC3339))
		impl.aliveMembership.Put(receivedPKIID, &protoext.SignedGossipMessage{GossipMessage: am.GossipMessage, Envelope: am.Envelope})

		var internalEndpoint string
		if am.Envelope.SecretEnvelope != nil {
			internalEndpoint = protoext.InternalEndpoint(am.Envelope.SecretEnvelope)
		}
		if preMem := impl.id2Member[hex.EncodeToString(receivedPKIID)]; preMem != nil {
			internalEndpoint = preMem.InternalEndpoint
		}
		impl.id2Member[hex.EncodeToString(receivedPKIID)] = &NetworkMember{
			ExternalEndpoint: am.GossipMessage.GetAliveMsg().Membership.Endpoint,
			InternalEndpoint: internalEndpoint,
			PKIid:            receivedPKIID,
			Metadata:         am.GossipMessage.GetAliveMsg().Membership.Metadata,
		}
	}

	for _, dm := range deadMembers {
		receivedPKIID := dm.GossipMessage.GetAliveMsg().Membership.PkiId
		if bytes.Equal(receivedPKIID, impl.self.PKIid) {
			continue
		}
		now := time.Now()
		impl.deadLastTS[hex.EncodeToString(receivedPKIID)] = &timestamp{
			incTime:  tsToTime(dm.GossipMessage.GetAliveMsg().Timestamp.IncNum),
			lastSeen: now,
			seqNum:   dm.GossipMessage.GetAliveMsg().Timestamp.SeqNum,
		}
		impl.logger.Debugf("Last seen dead member %s at %s.", hex.EncodeToString(receivedPKIID), now.Format(time.RFC3339))
		impl.deadMembership.Put(receivedPKIID, &protoext.SignedGossipMessage{GossipMessage: dm.GossipMessage, Envelope: dm.Envelope})

		var internalEndpoint string
		if dm.Envelope.SecretEnvelope != nil {
			internalEndpoint = protoext.InternalEndpoint(dm.Envelope.SecretEnvelope)
		}
		if preMem := impl.id2Member[hex.EncodeToString(receivedPKIID)]; preMem != nil {
			internalEndpoint = preMem.InternalEndpoint
		}
		impl.id2Member[hex.EncodeToString(receivedPKIID)] = &NetworkMember{
			ExternalEndpoint: dm.GossipMessage.GetAliveMsg().Membership.Endpoint,
			InternalEndpoint: internalEndpoint,
			PKIid:            receivedPKIID,
			Metadata:         dm.GossipMessage.GetAliveMsg().Membership.Metadata,
		}
	}
}

func (impl *gossipDiscoveryImpl) updateAliveMember(aliveMember *protoext.SignedGossipMessage) {
	impl.mutex.Lock()
	defer impl.mutex.Unlock()

	aliveMsg := aliveMember.GossipMessage.GetAliveMsg()
	if aliveMsg == nil {
		return
	}

	pkiIDStr := hex.EncodeToString(aliveMsg.Membership.PkiId)
	var internalEndpoint string
	if preNetMem := impl.id2Member[pkiIDStr]; preNetMem != nil {
		internalEndpoint = preNetMem.InternalEndpoint
	}
	if aliveMember.Envelope.SecretEnvelope != nil {
		internalEndpoint = protoext.InternalEndpoint(aliveMember.Envelope.SecretEnvelope)
	}

	// 根据节点发送来的 alive 消息，更新节点信息
	impl.id2Member[pkiIDStr].ExternalEndpoint = aliveMsg.Membership.Endpoint
	impl.id2Member[pkiIDStr].Metadata = aliveMsg.Membership.Metadata
	impl.id2Member[pkiIDStr].InternalEndpoint = internalEndpoint

	impl.aliveLastTS[pkiIDStr].incTime = tsToTime(aliveMsg.Timestamp.IncNum)
	impl.aliveLastTS[pkiIDStr].seqNum = aliveMsg.Timestamp.SeqNum
	impl.aliveLastTS[pkiIDStr].lastSeen = time.Now()

	aliveMembership := impl.aliveMembership.MsgByID(aliveMsg.Membership.PkiId)
	if aliveMembership == nil {
		impl.logger.Debugf("Putting alive membership in map for node %s: %v.", pkiIDStr, *aliveMember)
		impl.aliveMembership.Put(aliveMsg.Membership.PkiId, &protoext.SignedGossipMessage{GossipMessage: aliveMember.GossipMessage, Envelope: aliveMember.Envelope})
	} else {
		impl.logger.Debugf("Updating alive membership for node %s, new info: %v.", pkiIDStr, protoext.AliveMessageToString(aliveMsg))
		aliveMembership.GossipMessage = aliveMember.GossipMessage
		aliveMembership.Envelope = aliveMember.Envelope
	}
}

func (impl *gossipDiscoveryImpl) resurrectMember(signedMsg *protoext.SignedGossipMessage, peerTime *pbgossip.PeerTime) {
	impl.mutex.Lock()

	membership := signedMsg.GossipMessage.GetAliveMsg().Membership
	pkiIDStr := hex.EncodeToString(membership.PkiId)

	// 在 aliveLastTS 和 aliveMembership 列表中将节点添加上
	now := time.Now()
	impl.aliveLastTS[pkiIDStr] = &timestamp{
		incTime:  tsToTime(peerTime.IncNum),
		lastSeen: now,
		seqNum:   peerTime.SeqNum,
	}
	impl.aliveMembership.Put(membership.PkiId, &protoext.SignedGossipMessage{GossipMessage: signedMsg.GossipMessage, Envelope: signedMsg.Envelope})

	var internalEndpoint string
	if preNetMem := impl.id2Member[pkiIDStr]; preNetMem != nil {
		internalEndpoint = preNetMem.InternalEndpoint
	}
	if signedMsg.Envelope.SecretEnvelope != nil {
		internalEndpoint = protoext.InternalEndpoint(signedMsg.Envelope.SecretEnvelope)
	}

	// 在成员列表中添加或者更新这个被复活的成员信息
	if impl.id2Member[pkiIDStr] == nil {
		impl.id2Member[pkiIDStr] = &NetworkMember{
			ExternalEndpoint: membership.Endpoint,
			InternalEndpoint: internalEndpoint,
			Metadata:         membership.Metadata,
			PKIid:            membership.PkiId,
		}
	} else {
		impl.id2Member[pkiIDStr].Metadata = membership.Metadata
		impl.id2Member[pkiIDStr].ExternalEndpoint = membership.Endpoint
		impl.id2Member[pkiIDStr].InternalEndpoint = internalEndpoint
		impl.id2Member[pkiIDStr].PKIid = membership.PkiId
	}

	// 将 deadLastTS 和 deadMembership 列表中节点的信息删除掉，保持与 aliveLastTS 和 aliveMembership 的互斥性。
	delete(impl.deadLastTS, pkiIDStr)
	impl.deadMembership.Remove(membership.PkiId)

	impl.mutex.Unlock()
}

func (impl *gossipDiscoveryImpl) handleAliveMessage(signedMsg *protoext.SignedGossipMessage) {
	if impl.isAliveMsgSentByMe(signedMsg) {
		return
	}

	pkiID := signedMsg.GossipMessage.GetAliveMsg().Membership.PkiId
	pkiIDStr := hex.EncodeToString(pkiID)
	peerTime := signedMsg.GossipMessage.GetAliveMsg().Timestamp

	impl.mutex.RLock()
	_, knownNetworkMember := impl.id2Member[pkiIDStr]
	impl.mutex.RUnlock()

	if !knownNetworkMember {
		// 本地没有存储过该节点
		impl.logger.Debugf("Meeting a new node %s.", pkiIDStr)
		impl.learnNewMembers([]*protoext.SignedGossipMessage{signedMsg}, []*protoext.SignedGossipMessage{})
		return
	}

	impl.mutex.RLock()
	lastAliveTS, isAlive := impl.aliveLastTS[pkiIDStr]
	lastDeadTS, isDead := impl.deadLastTS[pkiIDStr]
	impl.mutex.RUnlock()

	if !isAlive && !isDead {
		impl.logger.Panicf("Member %s with endpoint %s is known, but it is neither alive nor dead.", pkiIDStr, signedMsg.GossipMessage.GetAliveMsg().Membership.Endpoint)
		return
	}

	if isAlive && isDead {
		impl.logger.Panicf("Member %s with endpoint %s is known, but it is both alive and dead.", pkiIDStr, signedMsg.GossipMessage.GetAliveMsg().Membership.Endpoint)
		return
	}

	if isDead {
		if before(lastDeadTS, peerTime) {
			// 如果这个节点之前死了，但是现在又给我发送了 alive 消息，那么就让此节点再次复活
			impl.resurrectMember(signedMsg, peerTime)
			impl.logger.Debugf("The node %s is dead at %s, we receive alive message from it at %s, so we resurrected it.", pkiIDStr, lastDeadTS.lastSeen.Format(time.RFC3339), tsToTime(peerTime.IncNum))
		} else if !same(lastDeadTS, peerTime) {
			impl.logger.Debugf("This is the previous alive message, so we can't resurrect node %s.", pkiIDStr)
		}
		return
	}

	if isAlive {
		if before(lastAliveTS, peerTime) {
			// 一个新的 alive 消息，可以用来更新节点的信息
			impl.updateAliveMember(signedMsg)
		} else if !same(lastAliveTS, peerTime) {
			impl.logger.Debugf("This is the previous alive message from %s, last_alive_ts <%s> against received_alive_ts <%s>.", pkiIDStr, lastAliveTS.String(), peerTime.String())
		}
	}
}

func (impl *gossipDiscoveryImpl) sendMemResponse(target *pbgossip.Membership, internalPoint string, nonce uint64) {
	targetPeer := &NetworkMember{
		ExternalEndpoint: target.Endpoint,
		Metadata:         target.Metadata,
		PKIid:            target.PkiId,
		InternalEndpoint: internalPoint,
	}
	targetPKIIDStr := hex.EncodeToString(target.PkiId)

	var err error
	impl.mutex.RLock()
	var me = impl.selfAliveMessage
	impl.mutex.RUnlock()

	if me == nil {
		me, err = impl.getMySignedAliveMessage(true)
		if err != nil {
			impl.logger.Warnf("Failed acquiring my alive message, because %s, so i can't send MembershipResponse to %s.", err.Error(), targetPKIIDStr)
			return
		}
	}

	resp := impl.createMembershipResponse(me, targetPeer)
	if resp == nil {
		impl.logger.Warnf("Received an unexpected MembershipRequest from %s, closing connection to %s as a result.", targetPKIIDStr, targetPKIIDStr)
		impl.commService.CloseConn(targetPeer)
		return
	}

	gossipMessage := &pbgossip.GossipMessage{
		Tag:   pbgossip.GossipMessage_EMPTY,
		Nonce: nonce,
		Content: &pbgossip.GossipMessage_MemRes{
			MemRes: resp,
		},
	}
	signedGossipMessage, _ := protoext.NoopSign(gossipMessage)
	impl.commService.SendToPeer(targetPeer, signedGossipMessage)
}

func (impl *gossipDiscoveryImpl) sendMemRequest(member *NetworkMember, includeInternalEndpoint bool) {
	memRequest, err := impl.createMembershipRequest(includeInternalEndpoint)
	if err != nil {
		impl.logger.Warnf("Failed sending membership request to %s, because %s.", member.PKIid.String(), err.Error())
		return
	}

	signedMemReuqest, _ := protoext.NoopSign(memRequest)
	impl.commService.SendToPeer(member, signedMemReuqest)
}

func (impl *gossipDiscoveryImpl) handleMessage(receivedMsg protoext.ReceivedMessage) {
	if receivedMsg == nil {
		return
	}

	signedGossipMessage := receivedMsg.GetSignedGossipMessage()
	if signedGossipMessage.GossipMessage.GetAliveMsg() == nil && signedGossipMessage.GossipMessage.GetMemReq() == nil && signedGossipMessage.GossipMessage.GetMemRes() == nil {
		impl.logger.Warnf("Discovery can only handle alive message or membership request or membership response, but got %T.", signedGossipMessage.GossipMessage.Content)
		return
	}

	switch {
	case signedGossipMessage.GossipMessage.GetAliveMsg() != nil:
		// 设发送此 alive 消息 mi 的节点是 pi，将 mi 和存储在本地的所有由 pi 发送过来的 alive 消息进行比较，
		// 如果 mi 比其中的某个 alive 消息的时间戳早，那么这将代表 mi 消息已经失效了。
		//
		// CheckValid 一定要在 ValidateAliveMsg 之前，不然 TestValidation 测试函数不能通过测试。
		if !impl.aliveMsgStore.CheckValid(signedGossipMessage) {
			return
		}

		// 应该是检查消息是否被正确签名
		if !impl.cryptoService.ValidateAliveMsg(signedGossipMessage) {
			return
		}

		if impl.isAliveMsgSentByMe(signedGossipMessage) {
			return
		}

		// 将其他节点发送来的 alive 消息存储到消息存储库里。
		impl.aliveMsgStore.Add(signedGossipMessage)
		impl.handleAliveMessage(signedGossipMessage)
		impl.commService.Forward(receivedMsg)
		return
	case signedGossipMessage.GossipMessage.GetMemRes() != nil:
		memRes := signedGossipMessage.GossipMessage.GetMemRes()
		impl.pubsub.Publish(fmt.Sprintf("%d", signedGossipMessage.GossipMessage.Nonce), signedGossipMessage.GossipMessage.Nonce)
		for _, aliveEnvelope := range memRes.Alive {
			signedMsg, err := protoext.EnvelopeToSignedGossipMessage(aliveEnvelope)
			if err != nil {
				impl.logger.Errorf("Membership response contains an invalid alive message from an online peer %s: %s.", hex.EncodeToString(memRes.PkiId), err.Error())
				return
			}
			if signedMsg.GossipMessage.GetAliveMsg() == nil {
				impl.logger.Warnf("Expected alive message in membership response from peer %s, but got %T.", hex.EncodeToString(memRes.PkiId), signedMsg.GossipMessage.Content)
				return
			}
			if impl.aliveMsgStore.CheckValid(signedMsg) && impl.cryptoService.ValidateAliveMsg(signedMsg) {
				impl.handleAliveMessage(signedMsg)
			}
		}

		for _, deadEnvelope := range memRes.Dead {
			signedMsg, err := protoext.EnvelopeToSignedGossipMessage(deadEnvelope)
			if err != nil {
				impl.logger.Errorf("Membership response contains an invalid dead message from an online peer %s: %s.", hex.EncodeToString(memRes.PkiId), err.Error())
				return
			}
			if !impl.aliveMsgStore.CheckValid(signedMsg) || !impl.cryptoService.ValidateAliveMsg(signedMsg) {
				continue
			}

			deadMembers := []*protoext.SignedGossipMessage{}
			pkiIDStr := hex.EncodeToString(signedMsg.GossipMessage.GetAliveMsg().Membership.PkiId)
			impl.mutex.RLock()
			if _, known := impl.id2Member[pkiIDStr]; !known {
				deadMembers = append(deadMembers, signedMsg)
			}
			impl.mutex.RUnlock()
			impl.learnNewMembers([]*protoext.SignedGossipMessage{}, deadMembers)
		}
	case signedGossipMessage.GossipMessage.GetMemReq() != nil:
		memReq := signedGossipMessage.GossipMessage.GetMemReq()
		selfInfoGossipMsg, err := protoext.EnvelopeToSignedGossipMessage(memReq.SelfInformation)
		if err != nil {
			impl.logger.Warnf("Failed getting the alive message from the node that sent the MembershipRequest: %s.", err.Error())
			return
		}

		if !impl.cryptoService.ValidateAliveMsg(selfInfoGossipMsg) {
			return
		}

		if impl.aliveMsgStore.CheckValid(selfInfoGossipMsg) {
			impl.handleAliveMessage(selfInfoGossipMsg)
		}

		var internalEndpoint string
		if selfInfoGossipMsg.Envelope.SecretEnvelope != nil {
			internalEndpoint = protoext.InternalEndpoint(selfInfoGossipMsg.Envelope.SecretEnvelope)
		}

		go impl.sendMemResponse(selfInfoGossipMsg.GossipMessage.GetAliveMsg().Membership, internalEndpoint, signedGossipMessage.GossipMessage.Nonce)
		return
	}
}

func (impl *gossipDiscoveryImpl) isAliveMsgSentByMe(signedMsg *protoext.SignedGossipMessage) bool {
	aliveMsg := signedMsg.GossipMessage.GetAliveMsg()
	if !bytes.Equal(aliveMsg.Membership.PkiId, impl.self.PKIid) {
		return false
	}

	impl.mutex.RLock()
	differentExternalEndpoint := aliveMsg.Membership.Endpoint != impl.self.ExternalEndpoint
	impl.mutex.RUnlock()
	var differentInternalEndpoint bool
	if signedMsg.Envelope.SecretEnvelope != nil {
		internalEndpoint := protoext.InternalEndpoint(signedMsg.Envelope.SecretEnvelope)
		if internalEndpoint != "" {
			differentInternalEndpoint = internalEndpoint != impl.self.InternalEndpoint
		}
	}
	if differentExternalEndpoint || differentInternalEndpoint {
		impl.logger.Errorf("Received AliveMessage from a peer with the same PKI-ID as myself: %v.", signedMsg.GossipMessage)
	}

	return true
}

func (impl *gossipDiscoveryImpl) validateSelf() {
	internalEndpoint := impl.self.InternalEndpoint
	if len(internalEndpoint) == 0 {
		impl.logger.Panic("Internal endpoint is empty.")
	}

	internalEndpointSplit := strings.Split(internalEndpoint, ":")
	if len(internalEndpointSplit) != 2 {
		impl.logger.Panicf("The self internal endpoint %s is not formatted as 'host:port'.", internalEndpoint)
	}

	port, err := strconv.ParseInt(internalEndpointSplit[1], 10, 64)
	if err != nil {
		impl.logger.Panicf("The self internal endpoint has invalid port %s, because %s.", internalEndpointSplit[1], err.Error())
	}

	if port > int64(math.MaxUint16) {
		impl.logger.Panicf("The self internal endpoint %s's port takes more than 166 bits.", internalEndpoint)
	}

	impl.port = int(port)
}

func (impl *gossipDiscoveryImpl) sendAliveMessageRoutine() {
	for !impl.stopped() {
		time.Sleep(impl.config.AliveTimeInterval)
		if impl.aliveMembership.Size() == 0 {
			impl.logger.Debug("There is no alive member to send alive message to.")
			continue
		}
		aliveMsg, err := impl.getMySignedAliveMessage(true)
		if err != nil {
			impl.logger.Warnf("Failed creating alive message, because %s.", err.Error())
			return
		}
		impl.mutex.Lock()
		impl.selfAliveMessage = aliveMsg
		impl.mutex.Unlock()
		impl.commService.Gossip(aliveMsg)
	}
}

func (impl *gossipDiscoveryImpl) checkAliveRoutine() {
	for !impl.stopped() {
		time.Sleep(impl.config.AliveExpirationCheckInterval)
		dead := impl.getDeadMembers()
		if len(dead) > 0 {
			impl.logger.Debugf("Got %d dead members: %v.", len(dead), dead)
			impl.addDeadMembersAndRemoveThemFromAliveMap(dead)
		}
	}
}

func (impl *gossipDiscoveryImpl) handleMessagesRoutine() {
	for {
		select {
		case receivedMsg := <-impl.commService.Accept():
			impl.handleMessage(receivedMsg)
		case <-impl.stopCh:
			return
		}
	}

	// handleMessagesRoutine 代码不能写成下面的样子，不然会卡死：
	// for !impl.stopped(){
	// 	select {
	// 	case receivedMsg := <-impl.commService.Accept():
	// 		impl.handleMessage(receivedMsg)
	// }
}

func (impl *gossipDiscoveryImpl) reconnectToDeadRoutine() {
	for !impl.stopped() {
		wg := &sync.WaitGroup{}

		deadMembers := []*NetworkMember{}
		impl.mutex.RLock()
		for pkiID := range impl.deadLastTS {
			deadMembers = append(deadMembers, impl.id2Member[pkiID])
		}
		impl.mutex.RUnlock()

		for _, member := range deadMembers {
			wg.Add(1)
			go func(member *NetworkMember) {
				defer wg.Done()
				if impl.commService.Ping(member) {
					impl.logger.Debugf("Peer %s is dead before, but it can respond us now, so send MembershipRequest to him.", member.PKIid.String())
					// 将我的 InternalEndpoint 发送给对方。
					impl.sendMemRequest(member, true)
				} else {
					impl.logger.Debugf("Peer %s is still dead.", member.PKIid.String())
				}
			}(member)
		}

		wg.Wait()
		time.Sleep(impl.config.ReconnectInterval)
	}
}

func (impl *gossipDiscoveryImpl) handleEventsRoutine() {
	for {
		select {
		case deadPeer := <-impl.commService.PresumedDead():
			impl.mutex.RLock()
			_, isAlive := impl.aliveLastTS[deadPeer.String()]
			impl.mutex.RUnlock()
			if isAlive {
				// 被判定为已 dead 的节点还存在于 alive map 中，那么将其从 alive map 中删除，并添加到
				// dead map 中。
				impl.addDeadMembersAndRemoveThemFromAliveMap([]common.PKIid{deadPeer})
			}
		case changedPKIID := <-impl.commService.IdentitySwitch():
			impl.logger.Infof("Because peer %s has changed his PKI-ID, so we purge him from membership.", changedPKIID.String())
			impl.mutex.Lock()
			impl.aliveMembership.Remove(changedPKIID)
			impl.deadMembership.Remove(changedPKIID)
			delete(impl.aliveLastTS, changedPKIID.String())
			delete(impl.deadLastTS, changedPKIID.String())
			delete(impl.id2Member, changedPKIID.String())
			impl.mutex.Unlock()
		case <-impl.stopCh:
			return
		}
	}
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

// 不可导出的工具函数

func copyNetworkMember(member *NetworkMember) *NetworkMember {
	if member == nil {
		return nil
	} else {
		clone := &NetworkMember{}
		*clone = *member
		return clone
	}
}

func same(a *timestamp, b *pbgossip.PeerTime) bool {
	return (uint64(a.incTime.UnixNano()) == b.IncNum) && (a.seqNum == b.SeqNum)
}

func before(a *timestamp, b *pbgossip.PeerTime) bool {
	if uint64(a.incTime.UnixNano()) == b.IncNum && a.seqNum < b.SeqNum {
		return true
	}

	if uint64(a.incTime.UnixNano()) < b.IncNum {
		return true
	}

	return false
}

func tsToTime(ts uint64) time.Time {
	return time.Unix(0, int64(ts))
}
