package discovery

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/gossip/protoext"
	"github.com/11090815/hyperchain/gossip/util"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

var (
	aliveTimeInterval = time.Millisecond * 300
	defaultTestConfig = DiscoveryConfig{
		AliveTimeInterval:            aliveTimeInterval * 3,
		AliveExpirationTimeout:       10 * aliveTimeInterval,
		AliveExpirationCheckInterval: aliveTimeInterval,
		ReconnectInterval:            10 * aliveTimeInterval,
		MaxConnectionAttempts:        DefaultMaxConnectionAttempts,
		MsgExpirationFactor:          DefaultMsgExpirationFactor,
	}

	timeout = time.Second * 15
)

func init() {
	hlogging.ActivateSpec("debug")
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type mockReceivedMessage struct {
	msg  *protoext.SignedGossipMessage
	info *protoext.ConnectionInfo
}

func (mock *mockReceivedMessage) Respond(msg *pbgossip.GossipMessage) {
	panic("implement me")
}

func (mock *mockReceivedMessage) GetSignedGossipMessage() *protoext.SignedGossipMessage {
	return mock.msg
}

func (mock *mockReceivedMessage) GetSourceEnvelope() *pbgossip.Envelope {
	panic("implement me")
}

func (mock *mockReceivedMessage) GetConnectionInfo() *protoext.ConnectionInfo {
	return mock.info
}

func (mock *mockReceivedMessage) Ack(err error) {
	panic("implement me")
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type mockAnchorPeerTracker struct {
	anchorPeersEndpoint []string
}

func (mock *mockAnchorPeerTracker) IsAnchorPeer(endpoint string) bool {
	return util.Contains(endpoint, mock.anchorPeersEndpoint)
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type mockCommService struct {
	id                  string
	validatedMessagesCh chan *protoext.SignedGossipMessage
	identitySwitchCh    chan common.PKIid
	presumedDeadCh      chan common.PKIid
	detectedDeadCh      chan string
	receivedMsgsCh      chan protoext.ReceivedMessage
	signCount           uint32
	msgSent             uint32
	msgReceived         uint32
	streams             map[string]pbgossip.Gossip_GossipStreamClient
	conns               map[string]*grpc.ClientConn
	isShouldGossip      bool
	isDisableComm       bool
	lastSeqs            map[string]uint64

	mutex *sync.RWMutex
}

func (mock *mockCommService) ValidateAliveMsg(aliveMsg *protoext.SignedGossipMessage) bool {
	mock.mutex.RLock()
	ch := mock.validatedMessagesCh
	mock.mutex.RUnlock()

	if ch != nil {
		ch <- aliveMsg
	}

	return true
}

func (mock *mockCommService) SignMessage(aliveMsg *pbgossip.GossipMessage, internalEndpoint string) *pbgossip.Envelope {
	atomic.AddUint32(&mock.signCount, 1)

	secret := &pbgossip.Secret{
		InternalEndpoint: internalEndpoint,
	}
	signer := func(msg []byte) ([]byte, error) {
		return nil, nil
	}

	s, _ := protoext.NoopSign(aliveMsg)
	envelope := s.Envelope
	protoext.SignSecret(envelope, signer, secret)
	return envelope
}

func (mock *mockCommService) Gossip(msg *protoext.SignedGossipMessage) {
	if !mock.isShouldGossip || mock.isDisableComm {
		return
	}
	mock.mutex.RLock()
	defer mock.mutex.RUnlock()
	for _, conn := range mock.streams {
		conn.Send(msg.Envelope)
	}
}

func (mock *mockCommService) SendToPeer(peer *NetworkMember, msg *protoext.SignedGossipMessage) {
	if mock.isDisableComm {
		return
	}

	mock.mutex.RLock()
	_, exists := mock.streams[peer.ExternalEndpoint]
	mock.mutex.RUnlock()

	if !exists {
		if !mock.Ping(peer) {
			fmt.Printf("Ping to %s failed.\n", peer.ExternalEndpoint)
			return
		}
	}

	mock.mutex.RLock()
	// signedMsg, _ := protoext.NoopSign(msg.GossipMessage)
	mock.streams[peer.ExternalEndpoint].Send(msg.Envelope)
	mock.mutex.RUnlock()
	atomic.AddUint32(&mock.msgSent, 1)
}

func (mock *mockCommService) Ping(peer *NetworkMember) bool {
	if mock.isDisableComm {
		return false
	}
	mock.mutex.Lock()
	defer mock.mutex.Unlock()

	_, alreadyExists := mock.streams[peer.ExternalEndpoint]
	conn := mock.conns[peer.ExternalEndpoint]
	if !alreadyExists || conn.GetState() == connectivity.Shutdown {
		newConn, err := grpc.Dial(peer.ExternalEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return false
		}
		if stream, err := pbgossip.NewGossipClient(newConn).GossipStream(context.Background()); err == nil {
			mock.conns[peer.ExternalEndpoint] = newConn
			mock.streams[peer.ExternalEndpoint] = stream
			return true
		}
		return false
	}
	if _, err := pbgossip.NewGossipClient(conn).Ping(context.Background(), &pbgossip.Empty{}); err == nil {
		return true
	}
	return false
}

func (mock *mockCommService) Accept() <-chan protoext.ReceivedMessage {
	return mock.receivedMsgsCh
}

func (mock *mockCommService) PresumedDead() <-chan common.PKIid {
	return mock.presumedDeadCh
}

func (mock *mockCommService) CloseConn(peer *NetworkMember) {
	mock.mutex.Lock()
	defer mock.mutex.Unlock()

	if _, exists := mock.streams[peer.ExternalEndpoint]; !exists {
		return
	}

	mock.streams[peer.ExternalEndpoint].CloseSend()
	mock.conns[peer.ExternalEndpoint].Close()
}

func (mock *mockCommService) Forward(msg protoext.ReceivedMessage) {
	mock.Gossip(msg.GetSignedGossipMessage())
}

func (mock *mockCommService) IdentitySwitch() <-chan common.PKIid {
	return mock.identitySwitchCh
}

func (mock *mockCommService) recordValidation(validatedMessages chan *protoext.SignedGossipMessage) {
	mock.mutex.Lock()
	mock.validatedMessagesCh = validatedMessages
	mock.mutex.Unlock()
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type mockGossipInstance struct {
	msgInterceptor func(*protoext.SignedGossipMessage)
	mockComm       *mockCommService
	discovery      Discovery
	syncInitiator  *time.Ticker
	stopCh         chan struct{}
	grpcServer     *grpc.Server
	listener       net.Listener
	isShouldGossip bool
	port           int
}

func (mock *mockGossipInstance) GossipStream(stream pbgossip.Gossip_GossipStreamServer) error {
	for {
		envelope, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		logger := mock.discoveryImpl().logger
		signedGossipMessage, err := protoext.EnvelopeToSignedGossipMessage(envelope)
		if err != nil {
			logger.Warnf("Failed deserializing GossipMessage from envelope, because %s.", err.Error())
			continue
		}
		mock.msgInterceptor(signedGossipMessage)

		var id common.PKIid
		if signedGossipMessage.GossipMessage.GetMemReq() != nil {
			var gossipMessage = &pbgossip.GossipMessage{}
			proto.Unmarshal(signedGossipMessage.GossipMessage.GetMemReq().SelfInformation.Payload, gossipMessage)
			id = gossipMessage.GetAliveMsg().Membership.PkiId
		} else if signedGossipMessage.GossipMessage.GetMemRes() != nil {
			id = signedGossipMessage.GossipMessage.GetMemRes().PkiId
		} else if signedGossipMessage.GossipMessage.GetAliveMsg() != nil {
			id = signedGossipMessage.GossipMessage.GetAliveMsg().Membership.PkiId
		}
		logger.Debugf("%s got message {%s} from %s.", mock.discoveryImpl().self.ExternalEndpoint, signedGossipMessage, id.String())
		mock.mockComm.receivedMsgsCh <- &mockReceivedMessage{
			msg: signedGossipMessage,
			info: &protoext.ConnectionInfo{
				PKIid: id,
			},
		}
		atomic.AddUint32(&mock.mockComm.msgReceived, 1)

		if aliveMsg := signedGossipMessage.GossipMessage.GetAliveMsg(); aliveMsg != nil {
			mock.tryForwardMessage(signedGossipMessage)
		}
	}
}

func (mock *mockGossipInstance) Stop() {
	if mock.syncInitiator != nil {
		mock.stopCh <- struct{}{}
	}
	mock.grpcServer.Stop()
	mock.listener.Close()
	mock.mockComm.mutex.Lock()
	for _, stream := range mock.mockComm.streams {
		stream.CloseSend()
	}
	for _, conn := range mock.mockComm.conns {
		conn.Close()
	}
	mock.mockComm.mutex.Unlock()
	mock.discovery.Stop()
}

func (mock *mockGossipInstance) Ping(context.Context, *pbgossip.Empty) (*pbgossip.Empty, error) {
	return &pbgossip.Empty{}, nil
}

func (mock *mockGossipInstance) tryForwardMessage(msg *protoext.SignedGossipMessage) {
	mock.mockComm.mutex.Lock()

	aliveMsg := msg.GossipMessage.GetAliveMsg()

	forward := false
	idStr := hex.EncodeToString(aliveMsg.Membership.PkiId)
	seqNum := aliveMsg.Timestamp.SeqNum

	if last, exists := mock.mockComm.lastSeqs[idStr]; exists {
		if last < seqNum {
			mock.mockComm.lastSeqs[idStr] = seqNum
			forward = true
		}
	} else {
		mock.mockComm.lastSeqs[idStr] = seqNum
		forward = true
	}

	mock.mockComm.mutex.Unlock()

	if forward {
		mock.mockComm.Gossip(msg)
	}
}

func (mock *mockGossipInstance) initiateSync(frequency time.Duration, peerNum int) {
	mock.syncInitiator = time.NewTicker(frequency)
	mock.stopCh = make(chan struct{})

	go func() {
		for {
			select {
			case <-mock.syncInitiator.C:
				mock.discovery.InitiateSync(peerNum)
			case <-mock.stopCh:
				mock.syncInitiator.Stop()
				return
			}
		}
	}()
}

func (mock *mockGossipInstance) discoveryImpl() *gossipDiscoveryImpl {
	return mock.discovery.(*gossipDiscoveryImpl)
}

func (mock *mockGossipInstance) sendMsgCount() int {
	return int(atomic.LoadUint32(&mock.mockComm.msgSent))
}

func (mock *mockGossipInstance) receivedMsgCount() int {
	return int(atomic.LoadUint32(&mock.mockComm.msgReceived))
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

var noopPolicy = func(remotePeer *NetworkMember) (Sieve, EnvelopeFilter) {
	return func(message *protoext.SignedGossipMessage) bool {
			return true
		}, func(message *protoext.SignedGossipMessage) *pbgossip.Envelope {
			return message.Envelope
		}
}

func createDiscoveryInstance(port int, id string, bootstrapPeers []string) *mockGossipInstance {
	tracker := &mockAnchorPeerTracker{}
	interceptor := func(*protoext.SignedGossipMessage) {}
	return createDiscoveryInstanceWithAnchorPeerTracker(port, id, bootstrapPeers, true, noopPolicy, interceptor, defaultTestConfig, tracker, nil)
}

func createDiscoveryInstanceWithInterceptor(port int, id string, bootstrapPeers []string, shouldGossip bool, policy DisclosurePolicy, msgInterceptor func(*protoext.SignedGossipMessage), config DiscoveryConfig) *mockGossipInstance {
	tracker := &mockAnchorPeerTracker{}
	return createDiscoveryInstanceWithAnchorPeerTracker(port, id, bootstrapPeers, shouldGossip, policy, msgInterceptor, config, tracker, nil)
}

func createDiscoveryInstanceWithAnchorPeerTracker(port int, id string, bootstrapPeers []string, shouldGossip bool, policy DisclosurePolicy, msgInterceptor func(*protoext.SignedGossipMessage), config DiscoveryConfig, anchorPeerTracker AnchorPeerTracker, logger *hlogging.HyperchainLogger) *mockGossipInstance {
	mockComm := &mockCommService{
		id:               id,
		identitySwitchCh: make(chan common.PKIid),
		presumedDeadCh:   make(chan common.PKIid, 10000),
		detectedDeadCh:   make(chan string, 10000),
		receivedMsgsCh:   make(chan protoext.ReceivedMessage, 1000),
		streams:          make(map[string]pbgossip.Gossip_GossipStreamClient),
		conns:            make(map[string]*grpc.ClientConn),
		lastSeqs:         make(map[string]uint64),
		isShouldGossip:   shouldGossip,
		isDisableComm:    false,
		mutex:            &sync.RWMutex{},
	}

	endpoint := fmt.Sprintf("localhost:%d", port)
	self := NetworkMember{
		Metadata:         []byte{},
		PKIid:            []byte(endpoint),
		ExternalEndpoint: endpoint,
		InternalEndpoint: endpoint,
	}

	listenAddress := fmt.Sprintf("%s:%d", "", port)
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		panic(err)
	}
	server := grpc.NewServer()
	config.BootstrapPeers = bootstrapPeers

	if logger == nil {
		logger = util.GetLogger(util.DiscoveryLogger, endpoint)
	}

	discovery := NewDiscoveryService(self, mockComm, mockComm, policy, config, anchorPeerTracker, logger)
	for _, bootPeer := range bootstrapPeers {
		discovery.Connect(NetworkMember{ExternalEndpoint: bootPeer, InternalEndpoint: bootPeer}, func() (*PeerIdentification, error) {
			return &PeerIdentification{SelfOrg: true, PKIid: common.PKIid(bootPeer)}, nil
		})
	}

	mockGossipInst := &mockGossipInstance{
		msgInterceptor: msgInterceptor,
		mockComm:       mockComm,
		discovery:      discovery,
		isShouldGossip: shouldGossip,
		port:           port,
		grpcServer:     server,
		listener:       listener,
	}

	pbgossip.RegisterGossipServer(server, mockGossipInst)

	go server.Serve(listener)

	return mockGossipInst
}

func TestNetworkMemberClone(t *testing.T) {
	nm := &NetworkMember{
		PKIid: common.PKIid("abc"),
		Properties: &pbgossip.Properties{
			LedgerHeight: 1,
			LeftChannel:  true,
		},
		Envelope: &pbgossip.Envelope{
			Payload: []byte("abc"),
		},
		InternalEndpoint: "internal",
		Metadata:         []byte("abc"),
		ExternalEndpoint: "endpoint",
	}

	clone := nm.Clone()
	fmt.Println(clone.String())
	require.Equal(t, clone.Properties.LedgerHeight, nm.Properties.LedgerHeight)
	require.Equal(t, clone.Properties.LeftChannel, nm.Properties.LeftChannel)
	require.Equal(t, clone.Envelope.Payload, nm.Envelope.Payload)
	require.False(t, nm.Properties == clone.Properties)
	require.False(t, nm.Envelope == clone.Envelope)
}

func TestToString(t *testing.T) {
	nm := NetworkMember{
		ExternalEndpoint: "a",
		InternalEndpoint: "b",
	}
	require.Equal(t, "b", nm.PreferredEndpoint())

	nm.InternalEndpoint = ""
	require.Equal(t, "a", nm.PreferredEndpoint())

	now := time.Now()
	ts := &timestamp{
		incTime: now,
		seqNum:  uint64(42),
	}
	require.Equal(t, fmt.Sprintf("timestamp{incTime: %s, seqNum: %d}", ts.incTime.Format(time.RFC3339), ts.seqNum), ts.String())
}

func TestBadMessageToHandle(t *testing.T) {
	inst := createDiscoveryInstance(2048, "test-peer", []string{})
	defer inst.Stop()
	inst.discovery.(*gossipDiscoveryImpl).handleMessage(nil)

	s, _ := protoext.NoopSign(&pbgossip.GossipMessage{
		Content: &pbgossip.GossipMessage_DataMsg{
			DataMsg: &pbgossip.DataMessage{},
		},
	})
	inst.discovery.(*gossipDiscoveryImpl).handleMessage(&mockReceivedMessage{
		msg: s,
	})
}

func TestConnect(t *testing.T) {
	nodeNum := 3
	instances := []*mockGossipInstance{}

	// firstSentMemReqMsgs := make(chan *protoext.SignedGossipMessage, nodeNum)
	for i := 0; i < nodeNum; i++ {
		inst := createDiscoveryInstance(2048+i, fmt.Sprintf("test-peer@%d", i), []string{})

		instances = append(instances, inst)
		endpoint := fmt.Sprintf("localhost:%d", 2048+(i+1)%10)
		nm := NetworkMember{ExternalEndpoint: endpoint, PKIid: []byte(endpoint)}
		inst.discovery.Connect(nm, func() (*PeerIdentification, error) {
			return &PeerIdentification{SelfOrg: false, PKIid: []byte(endpoint)}, nil
		})
	}

	time.Sleep(time.Second * 3)
	fullMembership := func() bool {
		return nodeNum-1 == len(instances[nodeNum-1].discovery.GetMembership())
	}
	waitUntilTimeoutOrFail(t, fullMembership, timeout)

	require.Equal(t, nodeNum-1, len(instances[util.RandomIntn(nodeNum)].discovery.GetMembership()))

	discInst := instances[util.RandomIntn(len(instances))].discovery.(*gossipDiscoveryImpl)
	memberReq, _ := discInst.createMembershipRequest(true)
	signedAliveGossipMessage, _ := protoext.EnvelopeToSignedGossipMessage(memberReq.GetMemReq().SelfInformation)
	require.NotNil(t, signedAliveGossipMessage.Envelope.SecretEnvelope)

	memberReq2, _ := discInst.createMembershipRequest(false)
	signedAliveGossipMessage2, _ := protoext.EnvelopeToSignedGossipMessage(memberReq2.GetMemReq().SelfInformation)
	require.Nil(t, signedAliveGossipMessage2.Envelope.SecretEnvelope)

	stopInstances(t, instances)
}

func TestNoSigningIfNoMembership(t *testing.T) {
	inst := createDiscoveryInstance(2048, "foreveralone", nil)
	defer inst.Stop()
	time.Sleep(defaultTestConfig.AliveTimeInterval * 10)
	require.Zero(t, atomic.LoadUint32(&inst.mockComm.signCount))
	inst.discovery.InitiateSync(10000)
	require.Zero(t, atomic.LoadUint32(&inst.mockComm.signCount))
}

func TestValidation(t *testing.T) {
	// wrapReceivedMessage := func(msg *protoext.SignedGossipMessage) protoext.ReceivedMessage {
	// 	return &mockReceivedMessage{
	// 		msg:  msg,
	// 		info: &protoext.ConnectionInfo{
	// 			PKIid: common.PKIid("testID"),
	// 		},
	// 	}
	// }

	requestMessagesReceived := make(chan *protoext.SignedGossipMessage, 100)
	responseMessagesReceived := make(chan *protoext.SignedGossipMessage, 100)
	aliveMessagesReceived := make(chan *protoext.SignedGossipMessage, 5000)

	var membershipRequest atomic.Value
	var membershipResponseWithAlivePeers atomic.Value
	var membershipResponseWithDeadPeers atomic.Value

	recordMembershipRequest := func(req *protoext.SignedGossipMessage) {
		msg, _ := protoext.EnvelopeToSignedGossipMessage(req.GossipMessage.GetMemReq().SelfInformation)
		fmt.Println("msg >>>", msg.String())
		fmt.Println("req >>>", req.String())

		membershipRequest.Store(req)
		requestMessagesReceived <- msg
	}

	recordMembershipResponse := func(res *protoext.SignedGossipMessage) {
		memRes := res.GossipMessage.GetMemRes()
		if len(memRes.GetAlive()) > 0 {
			membershipResponseWithAlivePeers.Store(res)
		}
		if len(memRes.GetDead()) > 0 {
			membershipResponseWithDeadPeers.Store(res)
		}
		responseMessagesReceived <- res
	}

	interceptor := func (msg *protoext.SignedGossipMessage) {
		if msg.GossipMessage.GetMemReq() != nil {
			recordMembershipRequest(msg)
			return
		}

		if msg.GossipMessage.GetMemRes() != nil {
			recordMembershipResponse(msg)
		}

		aliveMessagesReceived <- msg
	}

	p1 := createDiscoveryInstanceWithInterceptor(2048, "p1", []string{bootPeer(2050)}, true, noopPolicy, interceptor, defaultTestConfig)
	p2 := createDiscoveryInstance(2049, "p2", []string{bootPeer(2048)})
	p3 := createDiscoveryInstance(2050, "p3", nil)

	instances := []*mockGossipInstance{p1, p2, p3}
	defer stopInstances(t, instances)
	assertMembership(t, instances, 2)
	time.Sleep(time.Second)

}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

func waitUntilTimeoutOrFail(t *testing.T, pred func() bool, timeout time.Duration) {
	start := time.Now()
	limit := start.UnixNano() + timeout.Nanoseconds()

	for time.Now().UnixNano() < limit {
		if pred() {
			return
		}
		time.Sleep(timeout / 10)
	}
	require.Fail(t, "Timeout expired!")
}

func waitUntilOrFailBlocking(t *testing.T, f func()) {
	successCh := make(chan struct{})
	go func() {
		f()
		close(successCh)
	}()

	select {
	case <-time.NewTimer(timeout).C:
		require.Fail(t, "Timeout expired!")
	case <-successCh:
		return
	}
}

func stopInstances(t *testing.T, instances []*mockGossipInstance) {
	wg := &sync.WaitGroup{}
	for _, inst := range instances {
		wg.Add(1)
		go func(inst *mockGossipInstance) {
			defer wg.Done()
			inst.Stop()
		}(inst)
	}
	waitUntilOrFailBlocking(t, wg.Wait)
}

func bootPeer(port int) string {
	return fmt.Sprintf("localhost:%d", port)
}

func assertMembership(t *testing.T, instances []*mockGossipInstance, expectedNum int) {
	wg := &sync.WaitGroup{}
	wg.Add(len(instances))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, inst := range instances {
		go func(ctx context.Context, inst *mockGossipInstance) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case <-time.After(timeout/10):
				if len(inst.discovery.GetMembership()) == expectedNum {
					return
				}
			}
		}(ctx, inst)
	}

	wg.Wait()
	require.NoError(t, ctx.Err())
}
