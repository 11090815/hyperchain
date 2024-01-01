package discovery

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/gossip/gossip/msgstore"
	"github.com/11090815/hyperchain/gossip/protoext"
	"github.com/11090815/hyperchain/gossip/util"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

	timeout = time.Second * time.Duration(15)
)

func init() {
	hlogging.Init(hlogging.Config{
		Format:  hlogging.ShortFuncFormat,
		LogSpec: "debug",
	})
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

func (mock *mockReceivedMessage) GetEnvelope() *pbgossip.Envelope {
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
	mock                *mock.Mock
	mutex               *sync.RWMutex
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

	if mock.mock != nil {
		mock.mock.Called(peer, msg)
	}

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

	if mock.mock != nil {
		mock.mock.Called()
	}

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

		if mock.msgInterceptor != nil {
			mock.msgInterceptor(signedGossipMessage)
		}

		var id common.PKIid
		var endpoint string
		if signedGossipMessage.GossipMessage.GetMemReq() != nil {
			var gossipMessage = &pbgossip.GossipMessage{}
			proto.Unmarshal(signedGossipMessage.GossipMessage.GetMemReq().SelfInformation.Payload, gossipMessage)
			id = gossipMessage.GetAliveMsg().Membership.PkiId
			endpoint = gossipMessage.GetAliveMsg().Membership.Endpoint
		} else if signedGossipMessage.GossipMessage.GetMemRes() != nil {
			id = signedGossipMessage.GossipMessage.GetMemRes().PkiId
			endpoint = signedGossipMessage.GossipMessage.GetMemRes().Endpoint
		} else if signedGossipMessage.GossipMessage.GetAliveMsg() != nil {
			id = signedGossipMessage.GossipMessage.GetAliveMsg().Membership.PkiId
			endpoint = signedGossipMessage.GossipMessage.GetAliveMsg().Membership.Endpoint
		}
		logger.Debugf("Got message {%s} from %s@%s.", signedGossipMessage, id.String(), endpoint)
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
	wrapReceivedMessage := func(msg *protoext.SignedGossipMessage) protoext.ReceivedMessage {
		return &mockReceivedMessage{
			msg: msg,
			info: &protoext.ConnectionInfo{
				PKIid: common.PKIid("testID"),
			},
		}
	}

	requestMessagesReceived := make(chan *protoext.SignedGossipMessage, 100)
	responseMessagesReceived := make(chan *protoext.SignedGossipMessage, 100)
	aliveMessagesReceived := make(chan *protoext.SignedGossipMessage, 5000)

	var membershipRequest atomic.Value
	var membershipResponseWithAlivePeers atomic.Value
	var membershipResponseWithDeadPeers atomic.Value

	recordMembershipRequest := func(req *protoext.SignedGossipMessage) {
		msg, _ := protoext.EnvelopeToSignedGossipMessage(req.GossipMessage.GetMemReq().SelfInformation)
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

	interceptor := func(msg *protoext.SignedGossipMessage) {
		if msg.GossipMessage.GetMemReq() != nil {
			recordMembershipRequest(msg)
			return
		}

		if msg.GossipMessage.GetMemRes() != nil {
			recordMembershipResponse(msg)
			return
		}

		aliveMessagesReceived <- msg
	}

	p1 := createDiscoveryInstanceWithInterceptor(2048, "p1", []string{bootPeer(2050)}, true, noopPolicy, interceptor, defaultTestConfig)
	p2 := createDiscoveryInstance(2049, "p2", []string{bootPeer(2048)})
	p3 := createDiscoveryInstance(2050, "p3", nil)

	instances := []*mockGossipInstance{p1, p2, p3}
	defer stopInstances(t, instances)
	assertMembership(t, instances, 2)

	instances = []*mockGossipInstance{p1, p2}

	p3.Stop()

	assertMembership(t, instances, 1)

	p1.discovery.InitiateSync(1)

	waitUntilTimeoutOrFail(t, func() bool {
		return membershipResponseWithDeadPeers.Load() != nil
	}, timeout)

	p1.Stop()
	p2.Stop()

	close(aliveMessagesReceived)
	t.Log("Record", len(aliveMessagesReceived), "alive messages.")
	t.Log("Record", len(requestMessagesReceived), "request messages.")
	t.Log("Record", len(responseMessagesReceived), "response messages.")

	require.NotNil(t, membershipRequest.Load())
	require.NotNil(t, membershipResponseWithAlivePeers.Load())

	p4 := createDiscoveryInstance(4096, "p4", nil)
	validatedMessages := make(chan *protoext.SignedGossipMessage, 5000)
	p4.mockComm.recordValidation(validatedMessages)

	tmpMsgs := make(chan *protoext.SignedGossipMessage, 5000)
	for msg := range aliveMessagesReceived {
		p4.mockComm.receivedMsgsCh <- wrapReceivedMessage(msg)
		tmpMsgs <- msg
	}

	policy := protoext.NewGossipMessageComparator(0)
	msgStore := msgstore.NewMessageStore(policy, func(interface{}) {})
	close(tmpMsgs)
	for msg := range tmpMsgs {
		if msgStore.Add(msg) {
			expectedMessage := <-validatedMessages
			require.Equal(t, expectedMessage.String(), msg.String())
		}
	}
	require.Empty(t, validatedMessages)
	p4.Stop()

	req := membershipRequest.Load().(*protoext.SignedGossipMessage)
	res := membershipResponseWithDeadPeers.Load().(*protoext.SignedGossipMessage)
	require.Len(t, res.GossipMessage.GetMemRes().GetAlive(), 2)
	require.Len(t, res.GossipMessage.GetMemRes().GetDead(), 1)

	for _, testCase := range []struct {
		name                  string
		expectedAliveMessages int
		port                  int
		message               *protoext.SignedGossipMessage
		shouldBeRevalidated   bool
	}{
		{
			name:                  "membership request",
			expectedAliveMessages: 1,
			message:               req,
			port:                  1997,
			shouldBeRevalidated:   true,
		},
		{
			name:                  "membership response",
			expectedAliveMessages: 3,
			message:               res,
			port:                  1998,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			peer := createDiscoveryInstance(testCase.port, "peer", nil)
			validatedMessages := make(chan *protoext.SignedGossipMessage, testCase.expectedAliveMessages)
			peer.mockComm.recordValidation(validatedMessages)

			peer.mockComm.receivedMsgsCh <- wrapReceivedMessage(testCase.message)

			for i := 0; i < testCase.expectedAliveMessages; i++ {
				validatedMsg := <-validatedMessages
				peer.mockComm.receivedMsgsCh <- wrapReceivedMessage(validatedMsg)
			}

			for i := 0; i < testCase.expectedAliveMessages; i++ {
				<-validatedMessages
			}

			require.Empty(t, validatedMessages)
			if !testCase.shouldBeRevalidated {
				close(validatedMessages)
			}

			peer.mockComm.receivedMsgsCh <- wrapReceivedMessage(testCase.message)
			peer.mockComm.receivedMsgsCh <- wrapReceivedMessage(testCase.message)

			waitUntilTimeoutOrFail(t, func() bool {
				return len(peer.mockComm.receivedMsgsCh) == 0
			}, timeout)
			peer.Stop()
		})
	}
}

func TestUpdate(t *testing.T) {
	nodeNum := 5
	bootPeers := []string{bootPeer(2048), bootPeer(2049)}
	instances := []*mockGossipInstance{}

	inst := createDiscoveryInstance(2048, "p1", bootPeers)
	instances = append(instances, inst)

	inst = createDiscoveryInstance(2049, "p2", bootPeers)
	instances = append(instances, inst)

	for i := 3; i <= nodeNum; i++ {
		id := fmt.Sprintf("p%d", i)
		inst = createDiscoveryInstance(2047+i, id, bootPeers)
		instances = append(instances, inst)
	}

	fullMembership := func() bool {
		return len(instances[nodeNum-1].discovery.GetMembership()) == nodeNum-1
	}

	waitUntilTimeoutOrFail(t, fullMembership, timeout)

	instances[0].discovery.UpdateMetadata([]byte("abcd"))
	instances[nodeNum-1].discovery.UpdateExternalEndpoint("localhost:4096")

	checkMembership := func() bool {
		for _, member := range instances[nodeNum-1].discovery.GetMembership() {
			if bytes.Equal(member.PKIid, instances[0].discovery.(*gossipDiscoveryImpl).self.PKIid) {
				if string(member.Metadata) != "abcd" {
					return false
				}
			}
		}

		for _, member := range instances[0].discovery.GetMembership() {
			if bytes.Equal(member.PKIid, instances[nodeNum-1].discoveryImpl().self.PKIid) {
				if member.ExternalEndpoint != "localhost:4096" {
					return false
				}
			}
		}
		return true
	}

	waitUntilTimeoutOrFail(t, checkMembership, timeout)
	stopInstances(t, instances)
}

func TestInitiateSync(t *testing.T) {
	nodeNum := 10
	bootPeers := []string{bootPeer(2048), bootPeer(2049)}
	instances := []*mockGossipInstance{}

	stopped := uint32(0)

	for i := 1; i <= nodeNum; i++ {
		id := fmt.Sprintf("p%d", i)
		inst := createDiscoveryInstanceWithInterceptor(2047+i, id, bootPeers, false, noopPolicy, nil, defaultTestConfig)
		instances = append(instances, inst)

		go func() {
			for {
				if atomic.LoadUint32(&stopped) == uint32(1) {
					return
				}
				time.Sleep(defaultTestConfig.AliveExpirationTimeout / 3)
				inst.discovery.InitiateSync(9)
			}
		}()
	}

	time.Sleep(defaultTestConfig.AliveExpirationTimeout * 4)
	assertMembership(t, instances, nodeNum-1)
	atomic.StoreUint32(&stopped, 1)
	stopInstances(t, instances)
}

func TestSelf(t *testing.T) {
	inst := createDiscoveryInstance(2048, "p1", nil)
	defer inst.Stop()

	env := inst.discovery.Self().Envelope
	signedMsg, err := protoext.EnvelopeToSignedGossipMessage(env)
	require.NoError(t, err)
	member := signedMsg.GossipMessage.GetAliveMsg().Membership
	require.Equal(t, "localhost:2048", member.Endpoint)
	require.Equal(t, []byte("localhost:2048"), member.PkiId)

	require.Equal(t, "localhost:2048", inst.discoveryImpl().self.ExternalEndpoint)
	require.Equal(t, common.PKIid("localhost:2048"), inst.discoveryImpl().self.PKIid)
}

func TestExpiration(t *testing.T) {
	nodeNum := 5
	bootPeers := []string{bootPeer(2048), bootPeer(2049)}
	instances := []*mockGossipInstance{}

	inst1 := createDiscoveryInstance(2048, "p1", bootPeers)
	instances = append(instances, inst1)

	inst2 := createDiscoveryInstance(2049, "p2", bootPeers)
	instances = append(instances, inst2)

	for i := 3; i <= nodeNum; i++ {
		id := fmt.Sprintf("p%d", i)
		inst := createDiscoveryInstance(2047+i, id, bootPeers)
		instances = append(instances, inst)
	}

	assertMembership(t, instances, nodeNum-1)

	waitUntilOrFailBlocking(t, instances[nodeNum-1].Stop)
	waitUntilOrFailBlocking(t, instances[nodeNum-2].Stop)

	assertMembership(t, instances[:nodeNum-2], nodeNum-3)

	wg := &sync.WaitGroup{}
	for i, inst := range instances {
		if i+2 == nodeNum {
			break
		}
		wg.Add(1)
		go func(inst *mockGossipInstance) {
			defer wg.Done()
			inst.Stop()
		}(inst)
	}

	waitUntilOrFailBlocking(t, wg.Wait)
}

func TestGetFullMembership(t *testing.T) {
	nodeNum := 15
	bootPeers := []string{bootPeer(2048), bootPeer(2049)}
	instances := []*mockGossipInstance{}

	for i := 3; i <= nodeNum; i++ {
		id := fmt.Sprintf("p%d", i)
		inst := createDiscoveryInstance(2047+i, id, bootPeers)
		instances = append(instances, inst)
	}

	time.Sleep(time.Second)

	inst1 := createDiscoveryInstance(2048, "p1", bootPeers)
	instances = append(instances, inst1)

	inst2 := createDiscoveryInstance(2049, "p2", bootPeers)
	instances = append(instances, inst2)

	assertMembership(t, instances, nodeNum-1)

	for _, inst := range instances {
		for _, member := range inst.discovery.GetMembership() {
			require.NotEmpty(t, member.InternalEndpoint)
			require.NotEmpty(t, member.ExternalEndpoint)
		}
	}

	for _, inst := range instances {
		for _, member := range inst.discovery.GetMembership() {
			require.Equal(t, string(member.PKIid), inst.discovery.Lookup(member.PKIid).ExternalEndpoint)
			require.Equal(t, member.PKIid, inst.discovery.Lookup(member.PKIid).PKIid)
		}
	}

	stopInstances(t, instances)
}

func TestGossipDiscoveryStopping(t *testing.T) {
	inst := createDiscoveryInstance(2048, "p1", []string{bootPeer(2048)})
	time.Sleep(time.Second)
	waitUntilOrFailBlocking(t, inst.Stop)
}

func TestConvergence(t *testing.T) {
	instances := []*mockGossipInstance{}
	for _, i := range []int{1, 5, 9} {
		port := 2047 + i
		id := fmt.Sprintf("p%d", i)
		leader := createDiscoveryInstance(port, id, nil)
		instances = append(instances, leader)

		for j := 1; j <= 3; j++ {
			id := fmt.Sprintf("p%d", i+j)
			minion := createDiscoveryInstance(2047+j+i, id, []string{bootPeer(port)})
			instances = append(instances, minion)
		}
	}

	assertMembership(t, instances, 3)
	connector := createDiscoveryInstance(4096, "p4096", []string{bootPeer(2048), bootPeer(2052), bootPeer(2056)})
	instances = append(instances, connector)
	assertMembership(t, instances, 12)
	connector.Stop()
	instances = instances[:len(instances)-1]
	assertMembership(t, instances, 11)
	stopInstances(t, instances)
}

func TestDisclosurePolicyWithPull(t *testing.T) {
	// Scenario: run 2 groups of peers that simulate 2 organizations:
	// {p0, p1, p2, p3, p4}
	// {p5, p6, p7, p8, p9}
	// Only peers that have an even id have external addresses
	// and only these peers should be published to peers of the other group,
	// while the only ones that need to know about them are peers
	// that have an even id themselves.
	// Furthermore, peers in different sets, should not know about internal addresses of
	// other peers.

	// This is a bootstrap map that matches for each peer its own bootstrap peer.
	// In practice (production) peers should only use peers of their orgs as bootstrap peers,
	// but the discovery layer is ignorant of organizations.
	bootPeerMap := map[int]int{
		8610: 8616,
		8611: 8610,
		8612: 8610,
		8613: 8610,
		8614: 8610,
		8615: 8616,
		8616: 8610,
		8617: 8616,
		8618: 8616,
		8619: 8616,
	}

	// This map matches each peer, the peers it should know about in the test scenario.
	peersThatShouldBeKnownToPeers := map[int][]int{
		8610: {8611, 8612, 8613, 8614, 8616, 8618},
		8611: {8610, 8612, 8613, 8614},
		8612: {8610, 8611, 8613, 8614, 8616, 8618},
		8613: {8610, 8611, 8612, 8614},
		8614: {8610, 8611, 8612, 8613, 8616, 8618},
		8615: {8616, 8617, 8618, 8619},
		8616: {8610, 8612, 8614, 8615, 8617, 8618, 8619},
		8617: {8615, 8616, 8618, 8619},
		8618: {8610, 8612, 8614, 8615, 8616, 8617, 8619},
		8619: {8615, 8616, 8617, 8618},
	}
	// Create the peers in the two groups
	instances1, instances2 := createDisjointPeerGroupsWithNoGossip(bootPeerMap)
	// Sleep a while to let them establish membership. This time should be more than enough
	// because the instances are configured to pull membership in very high frequency from
	// up to 10 peers (which results in - pulling from everyone)
	waitUntilTimeoutOrFail(t, func() bool {
		for _, inst := range append(instances1, instances2...) {
			// Ensure the expected membership is equal in size to the actual membership
			// of each peer.
			portsOfKnownMembers := portsOfMembers(inst.discovery.GetMembership())
			if len(peersThatShouldBeKnownToPeers[inst.port]) != len(portsOfKnownMembers) {
				return false
			}
		}
		return true
	}, timeout)
	for _, inst := range append(instances1, instances2...) {
		portsOfKnownMembers := portsOfMembers(inst.discovery.GetMembership())
		// Ensure the expected membership is equal to the actual membership
		// of each peer. the portsOfMembers returns a sorted slice so assert.Equal does the job.
		require.Equal(t, peersThatShouldBeKnownToPeers[inst.port], portsOfKnownMembers)
		// Next, check that internal endpoints aren't leaked across groups,
		for _, knownPeer := range inst.discovery.GetMembership() {
			// If internal endpoint is known, ensure the peers are in the same group
			// unless the peer in question is a peer that has a public address.
			// We cannot control what we disclose about ourselves when we send a membership request
			if len(knownPeer.InternalEndpoint) > 0 && inst.port%2 != 0 {
				bothInGroup1 := portOfEndpoint(knownPeer.ExternalEndpoint) < 8615 && inst.port < 8615
				bothInGroup2 := portOfEndpoint(knownPeer.ExternalEndpoint) >= 8615 && inst.port >= 8615
				require.True(t, bothInGroup1 || bothInGroup2, "%v knows about %v's internal endpoint", inst.port, knownPeer.InternalEndpoint)
			}
		}
	}

	t.Log("Shutting down instance 0...")
	// Now, we shutdown instance 0 and ensure that peers that shouldn't know it,
	// do not know it via membership requests
	stopInstances(t, []*mockGossipInstance{instances1[0]})
	time.Sleep(time.Second * 6)
	for _, inst := range append(instances1[1:], instances2...) {
		if peersThatShouldBeKnownToPeers[inst.port][0] == 8610 {
			require.Equal(t, 1, inst.discovery.(*gossipDiscoveryImpl).deadMembership.Size())
		} else {
			require.Equal(t, 0, inst.discovery.(*gossipDiscoveryImpl).deadMembership.Size())
		}
	}
	stopInstances(t, instances1[1:])
	stopInstances(t, instances2)
}

func TestCertificateChange(t *testing.T) {
	bootPeers := []string{bootPeer(42611), bootPeer(42612), bootPeer(42613)}
	p1 := createDiscoveryInstance(42611, "d1", bootPeers)
	p2 := createDiscoveryInstance(42612, "d2", bootPeers)
	p3 := createDiscoveryInstance(42613, "d3", bootPeers)

	// Wait for membership establishment
	assertMembership(t, []*mockGossipInstance{p1, p2, p3}, 2)

	// Shutdown the second peer
	waitUntilOrFailBlocking(t, p2.Stop)

	var pingCountFrom1 uint32
	var pingCountFrom3 uint32
	// Program mocks to increment ping counters
	p1.mockComm.mutex.Lock()
	p1.mockComm.mock = &mock.Mock{}
	p1.mockComm.mock.On("SendToPeer", mock.Anything, mock.Anything)
	p1.mockComm.mock.On("Ping").Run(func(arguments mock.Arguments) {
		atomic.AddUint32(&pingCountFrom1, 1)
	})
	p1.mockComm.mutex.Unlock()

	p3.mockComm.mutex.Lock()
	p3.mockComm.mock = &mock.Mock{}
	p3.mockComm.mock.On("SendToPeer", mock.Anything, mock.Anything)
	p3.mockComm.mock.On("Ping").Run(func(arguments mock.Arguments) {
		atomic.AddUint32(&pingCountFrom3, 1)
	})
	p3.mockComm.mutex.Unlock()

	pingCount1 := func() uint32 {
		return atomic.LoadUint32(&pingCountFrom1)
	}

	pingCount3 := func() uint32 {
		return atomic.LoadUint32(&pingCountFrom3)
	}

	c1 := pingCount1()
	c3 := pingCount3()

	// Ensure the first peer and third peer try to reconnect to it
	waitUntilTimeoutOrFail(t, func() bool {
		if pingCount1() > c1 && pingCount3() > c3 {
		}
		return pingCount1() > c1 && pingCount3() > c3
	}, timeout)

	// Tell the first peer that the second peer's PKI-ID has changed
	// So that it will purge it from the membership entirely
	p1.mockComm.identitySwitchCh <- common.PKIid("localhost:42612")

	c1 = pingCount1()
	c3 = pingCount3()
	// Ensure third peer tries to reconnect to it
	waitUntilTimeoutOrFail(t, func() bool {
		return pingCount3() > c3
	}, timeout)

	// Ensure the first peer ceases from trying
	require.Equal(t, c1, pingCount1())

	waitUntilOrFailBlocking(t, p1.Stop)
	waitUntilOrFailBlocking(t, p3.Stop)
}

func TestMsgStoreExpiration(t *testing.T) {
	// Starts 4 instances, wait for membership to build, stop 2 instances
	// Check that membership in 2 running instances become 2
	// Wait for expiration and check that alive messages and related entities in maps are removed in running instances
	nodeNum := 4
	bootPeers := []string{bootPeer(2048), bootPeer(2049)}
	instances := []*mockGossipInstance{}

	inst := createDiscoveryInstance(2048, "d1", bootPeers)
	instances = append(instances, inst)

	inst = createDiscoveryInstance(2049, "d2", bootPeers)
	instances = append(instances, inst)

	for i := 3; i <= nodeNum; i++ {
		id := fmt.Sprintf("d%d", i)
		inst = createDiscoveryInstance(2047+i, id, bootPeers)
		instances = append(instances, inst)
	}

	assertMembership(t, instances, nodeNum-1)

	waitUntilOrFailBlocking(t, instances[nodeNum-1].Stop)
	waitUntilOrFailBlocking(t, instances[nodeNum-2].Stop)

	assertMembership(t, instances[:len(instances)-2], nodeNum-3)

	checkMessages := func() bool {
		for _, inst := range instances[:len(instances)-2] {
			for _, downInst := range instances[len(instances)-2:] {
				downCastInst := inst.discoveryImpl()
				downCastInst.mutex.RLock()
				if _, exist := downCastInst.aliveLastTS[string(downInst.discoveryImpl().self.PKIid)]; exist {
					downCastInst.mutex.RUnlock()
					return false
				}
				if _, exist := downCastInst.deadLastTS[string(downInst.discoveryImpl().self.PKIid)]; exist {
					downCastInst.mutex.RUnlock()
					return false
				}
				if _, exist := downCastInst.id2Member[string(downInst.discoveryImpl().self.PKIid)]; exist {
					downCastInst.mutex.RUnlock()
					return false
				}
				if downCastInst.aliveMembership.MsgByID(downInst.discoveryImpl().self.PKIid) != nil {
					downCastInst.mutex.RUnlock()
					return false
				}
				if downCastInst.deadMembership.MsgByID(downInst.discoveryImpl().self.PKIid) != nil {
					downCastInst.mutex.RUnlock()
					return false
				}
				for _, am := range downCastInst.aliveMsgStore.Get() {
					m := am.(*protoext.SignedGossipMessage).GossipMessage.GetAliveMsg()
					if bytes.Equal(m.Membership.PkiId, downInst.discoveryImpl().self.PKIid) {
						downCastInst.mutex.RUnlock()
						return false
					}
				}
				downCastInst.mutex.RUnlock()
			}
		}
		return true
	}

	waitUntilTimeoutOrFail(t, checkMessages, defaultTestConfig.AliveExpirationTimeout*(DefaultMsgExpirationFactor+5))

	assertMembership(t, instances[:len(instances)-2], nodeNum-3)

	stopInstances(t, instances[:len(instances)-2])
}

func TestExpirationNoSecretEnvelope(t *testing.T) {
	l, err := zap.NewDevelopment()
	require.NoError(t, err)

	removed := make(chan struct{})
	logger := hlogging.NewHyperchainLogger(l, zap.Hooks(func(entry zapcore.Entry) error {
		if strings.Contains(entry.Message, "Removing member, whose endpoint is \"foo\"") {
			removed <- struct{}{}
		}
		return nil
	}))

	mockTracker := &mockAnchorPeerTracker{}
	msgStore := newAliveMsgStore(&gossipDiscoveryImpl{
		config: DiscoveryConfig{
			AliveExpirationTimeout: time.Millisecond,
		},
		mutex:             &sync.RWMutex{},
		aliveMembership:   util.NewMembershipStore(),
		deadMembership:    util.NewMembershipStore(),
		logger:            logger,
		anchorPeerTracker: mockTracker,
	})

	msg := &pbgossip.GossipMessage{
		Content: &pbgossip.GossipMessage_AliveMsg{
			AliveMsg: &pbgossip.AliveMessage{Membership: &pbgossip.Membership{
				Endpoint: "foo",
			}},
		},
	}

	sMsg, err := protoext.NoopSign(msg)
	require.NoError(t, err)

	msgStore.Add(sMsg)
	select {
	case <-removed:
	case <-time.After(time.Second * 10):
		t.Fatalf("timed out")
	}
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
	wg := sync.WaitGroup{}
	wg.Add(len(instances))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, inst := range instances {
		go func(ctx context.Context, inst *mockGossipInstance) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(timeout / 10):
					if len(inst.discovery.GetMembership()) == expectedNum {
						return
					}
				}
			}
		}(ctx, inst)
	}

	wg.Wait()
	require.NoError(t, ctx.Err())
}

func createDisjointPeerGroupsWithNoGossip(bootPeerMap map[int]int) ([]*mockGossipInstance, []*mockGossipInstance) {
	instances1 := []*mockGossipInstance{}
	instances2 := []*mockGossipInstance{}
	for group := 0; group < 2; group++ {
		for i := 0; i < 5; i++ {
			group := group
			id := fmt.Sprintf("id%d", group*5+i)
			port := 8610 + group*5 + i
			bootPeers := []string{bootPeer(bootPeerMap[port])}
			pol := discPolForPeer(port)
			inst := createDiscoveryInstanceWithInterceptor(8610+group*5+i, id, bootPeers, false, pol, nil, defaultTestConfig)
			inst.initiateSync(defaultTestConfig.AliveExpirationTimeout/3, 10)
			if group == 0 {
				instances1 = append(instances1, inst)
			} else {
				instances2 = append(instances2, inst)
			}
		}
	}
	return instances1, instances2
}

func discPolForPeer(selfPort int) DisclosurePolicy {
	return func(remotePeer *NetworkMember) (Sieve, EnvelopeFilter) {
		targetPortStr := strings.Split(remotePeer.ExternalEndpoint, ":")[1]
		targetPort, _ := strconv.ParseInt(targetPortStr, 10, 64)
		return func(msg *protoext.SignedGossipMessage) bool {
				portOfAliveMsgStr := strings.Split(msg.GossipMessage.GetAliveMsg().Membership.Endpoint, ":")[1]
				portOfAliveMsg, _ := strconv.ParseInt(portOfAliveMsgStr, 10, 64)

				if portOfAliveMsg < 8615 && targetPort < 8615 {
					return true
				}
				if portOfAliveMsg >= 8615 && targetPort >= 8615 {
					return true
				}

				// Else, expose peers with even ids to other peers with even ids
				return portOfAliveMsg%2 == 0 && targetPort%2 == 0
			}, func(msg *protoext.SignedGossipMessage) *pbgossip.Envelope {
				envelope := proto.Clone(msg.Envelope).(*pbgossip.Envelope)
				if selfPort < 8615 && targetPort >= 8615 {
					envelope.SecretEnvelope = nil
				}

				if selfPort >= 8615 && targetPort < 8615 {
					envelope.SecretEnvelope = nil
				}

				return envelope
			}
	}
}

func portOfEndpoint(endpoint string) int {
	port, _ := strconv.ParseInt(strings.Split(endpoint, ":")[1], 10, 64)
	return int(port)
}

func portsOfMembers(members []NetworkMember) []int {
	ports := make([]int, len(members))
	for i := range members {
		ports[i] = portOfEndpoint(members[i].ExternalEndpoint)
	}
	sort.Ints(ports)
	return ports
}
