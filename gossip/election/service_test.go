package election

import (
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/gossip/discovery"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func init() {
	hlogging.Init(hlogging.Config{
		Format:  hlogging.ShortFuncFormat,
		LogSpec: "debug",
	})
}

const (
	testStartupGracePeriod            = time.Millisecond * 500
	testMembershipSampleInterval      = time.Millisecond * 100
	testLeaderAliveThreshold          = time.Millisecond * 500
	testLeaderElectionDuration        = time.Millisecond * 500
	testLeadershipDeclarationInterval = testLeaderAliveThreshold / 2
	testPollInterval                  = time.Millisecond * 300
	testTimeout                       = time.Second * 5
)

var (
	testElectionConfig = ElectionConfig{
		StartupGracePeriod:       testStartupGracePeriod,
		MembershipSampleInterval: testMembershipSampleInterval,
		LeaderAliveThreshold:     testLeaderAliveThreshold,
		LeaderElectionDuration:   testLeaderElectionDuration,
	}
)

type peer struct {
	LeaderElectionService
	mock.Mock                              // 这玩意儿能改变方法逻辑
	mockedMethods      map[string]struct{} // 这玩意儿能辅助改变方法逻辑
	id                 common.PKIid
	peers              map[string]*peer
	msgCh              chan *pbgossip.GossipMessage
	leaderFromCallback bool
	callbackInvoked    bool
	sharedLock         *sync.RWMutex
	lock               *sync.RWMutex
}

func (p *peer) On(methodName string, arguments ...interface{}) *mock.Call {
	p.sharedLock.Lock()
	defer p.sharedLock.Unlock()
	p.mockedMethods[methodName] = struct{}{}
	return p.Mock.On(methodName, arguments...)
}

func (p *peer) Gossip(msg *pbgossip.GossipMessage) {
	p.sharedLock.RLock()
	defer p.sharedLock.RUnlock()

	if _, isMocked := p.mockedMethods["Gossip"]; isMocked {
		p.Called(msg)
		return
	}

	for _, member := range p.peers {
		if member.id.Equal(p.id) {
			continue
		}
		member.msgCh <- msg
	}
}

func (p *peer) Accept() <-chan *pbgossip.GossipMessage {
	p.sharedLock.RLock()
	defer p.sharedLock.RUnlock()

	if _, isMocked := p.mockedMethods["Accept"]; isMocked {
		args := p.Called()
		return args.Get(0).(<-chan *pbgossip.GossipMessage)
	}
	return p.msgCh
}

func (p *peer) CreateMessage(isDeclaration bool) *pbgossip.GossipMessage {
	return &pbgossip.GossipMessage{
		Tag: pbgossip.GossipMessage_CHAN_AND_ORG,
		Content: &pbgossip.GossipMessage_LeadershipMsg{
			LeadershipMsg: &pbgossip.LeadershipMessage{
				PkiId:         p.id,
				IsDeclaration: isDeclaration,
			},
		},
	}
}

func (p *peer) Peers() []discovery.NetworkMember {
	p.sharedLock.RLock()
	defer p.sharedLock.RUnlock()

	if _, isMocked := p.mockedMethods["Peers"]; isMocked {
		args := p.Called()
		return args.Get(0).([]discovery.NetworkMember)
	}

	var members []discovery.NetworkMember
	for _, member := range p.peers {
		members = append(members, discovery.NetworkMember{
			PKIid: member.id,
		})
	}

	return members
}

func (p *peer) ReportMetrics(isLeader bool) {
	// Called 会告诉 mock 对象一个方法已被调用，并获取一个参数数组以返回。如果调用出乎意料（即调用之前没有适当的 .On .Return() 调用），
	// 则会慌乱 如果设置了 Call.WaitFor，则会阻塞直到通道关闭或收到消息。
	p.Mock.Called(isLeader)
}

func (p *peer) Stop() {
	p.LeaderElectionService.Stop()
}

func (p *peer) leaderCallback(isLeader bool) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.leaderFromCallback = isLeader
	p.callbackInvoked = true
}

func (p *peer) isLeaderFromCallback() bool {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return p.leaderFromCallback
}

func (p *peer) isCallbackInvoked() bool {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return p.callbackInvoked
}

func createPeers(spawnInterval time.Duration, ids ...common.PKIid) []*peer {
	peers := make([]*peer, len(ids))
	members := make(map[string]*peer)
	sharedlock := &sync.RWMutex{}
	for i, id := range ids {
		p := createPeer(id, members, sharedlock)
		if spawnInterval != 0 {
			time.Sleep(spawnInterval)
		}
		peers[i] = p
	}
	return peers
}

func createPeer(id common.PKIid, members map[string]*peer, sharedlock *sync.RWMutex) *peer {
	return createPeerWithCostumeMetrics(id, members, sharedlock, func(mock.Arguments) {})
}

func createPeerWithCostumeMetrics(id common.PKIid, members map[string]*peer, sharedlock *sync.RWMutex, f func(mock.Arguments)) *peer {
	p := &peer{
		id:            id,
		peers:         members,
		sharedLock:    sharedlock,
		lock:          &sync.RWMutex{},
		msgCh:         make(chan *pbgossip.GossipMessage, 100),
		mockedMethods: make(map[string]struct{}),
	}
	p.On("ReportMetrics", mock.Anything).Run(f)
	p.LeaderElectionService = NewLeaderElectionService(p, id, p.leaderCallback, testElectionConfig, id.String())
	sharedlock.Lock()
	members[id.String()] = p
	sharedlock.Unlock()
	return p
}

func waitForLeaderElection(t *testing.T, peers []*peer) []string {
	return waitForMultipleLeadersElection(t, peers, 1)
}

func waitForMultipleLeadersElection(t *testing.T, peers []*peer, leadersNum int) []string {
	end := time.Now().Add(testTimeout)
	for time.Now().Before(end) {
		var leaders []string
		for _, p := range peers {
			if p.IsLeader() {
				leaders = append(leaders, p.id.String())
			}
		}
		if len(leaders) >= leadersNum {
			return leaders
		}
		time.Sleep(testPollInterval)
	}
	t.Fatal("No leader detected")
	return nil
}

func waitForBoolFunc(t *testing.T, f func() bool, expectedValue bool, msgAndArgs ...interface{}) {
	end := time.Now().Add(testTimeout)
	for time.Now().Before(end) {
		if f() == expectedValue {
			return
		}
		time.Sleep(testPollInterval)
	}
	require.Fail(t, fmt.Sprintf("Should be %t", expectedValue))
}

func TestMetrics(t *testing.T) {
	var wgLeader sync.WaitGroup
	var wgFollower sync.WaitGroup
	wgLeader.Add(1)
	wgFollower.Add(1)

	var once1 sync.Once
	var once2 sync.Once

	f := func(args mock.Arguments) {
		if args[0] == true {
			once1.Do(func() {
				wgLeader.Done()
			})
		} else {
			once2.Do(func() {
				wgFollower.Done()
			})
		}
	}

	p := createPeerWithCostumeMetrics(common.PKIid("peer0"), make(map[string]*peer), &sync.RWMutex{}, f)
	waitForLeaderElection(t, []*peer{p})

	wgLeader.Wait()
	// AssertCalled 断言方法已被调用。如果参数是指针类型，并且在调用模拟方法后底层值发生了变化，它可能会产生错误结果。
	p.AssertCalled(t, "ReportMetrics", true)

	p.Waive()
	require.False(t, p.IsLeader())

	wgFollower.Wait()
	p.AssertCalled(t, "ReportMetrics", false)

	waitForLeaderElection(t, []*peer{p})
}

func TestInitPeersAtSameTime(t *testing.T) {
	ids := []common.PKIid{
		common.PKIid("p9"),
		common.PKIid("p8"),
		common.PKIid("p7"),
		common.PKIid("p6"),
		common.PKIid("p5"),
		common.PKIid("p4"),
		common.PKIid("p3"),
		common.PKIid("p2"),
		common.PKIid("p1"),
		common.PKIid("p0"),
	}
	peers := createPeers(0, ids...)

	time.Sleep(testStartupGracePeriod + testLeaderElectionDuration)
	leaders := waitForLeaderElection(t, peers)
	isP0leader := peers[len(peers)-1].IsLeader()
	require.True(t, isP0leader)
	require.Len(t, leaders, 1)
	waitForBoolFunc(t, peers[len(peers)-1].isLeaderFromCallback, true)

	time.Sleep(testLeaderAliveThreshold * 6)
	isP1leader := peers[len(peers)-1].IsLeader()
	require.True(t, isP1leader)

}

func TestInitPeersStartAtIntervals(t *testing.T) {
	ids := []common.PKIid{
		common.PKIid("p3"),
		common.PKIid("p2"),
		common.PKIid("p1"),
		common.PKIid("p0"),
	}
	peers := createPeers(testStartupGracePeriod+testLeadershipDeclarationInterval, ids...)
	waitForLeaderElection(t, peers)
	require.True(t, peers[0].IsLeader())
}

func TestStop(t *testing.T) {
	ids := []common.PKIid{
		common.PKIid("p3"),
		common.PKIid("p2"),
		common.PKIid("p1"),
		common.PKIid("p0"),
	}
	peers := createPeers(0, ids...)
	var gossipCounter int32
	for i, p := range peers {
		p.On("Gossip", mock.Anything).Run(func(args mock.Arguments) {
			msg := args.Get(0).(*pbgossip.GossipMessage)
			atomic.AddInt32(&gossipCounter, 1)
			for j := range peers {
				if i == j {
					continue
				}
				peers[j].msgCh <- msg
			}
		})
	}
	waitForLeaderElection(t, peers)
	for _, p := range peers {
		p.Stop()
	}
	time.Sleep(testLeaderAliveThreshold)
	gossipCounterAfterStop := atomic.LoadInt32(&gossipCounter)
	time.Sleep(testLeaderAliveThreshold * 5)
	require.Equal(t, gossipCounterAfterStop, atomic.LoadInt32(&gossipCounter))
}

func TestConvergence(t *testing.T) {
	ids1 := []common.PKIid{
		common.PKIid("p3"),
		common.PKIid("p2"),
		common.PKIid("p1"),
		common.PKIid("p0"),
	}

	ids2 := []common.PKIid{
		common.PKIid("p4"),
		common.PKIid("p5"),
		common.PKIid("p6"),
		common.PKIid("p7"),
	}

	peers1 := createPeers(0, ids1...)
	peers2 := createPeers(0, ids2...)

	leaders1 := waitForLeaderElection(t, peers1)
	leaders2 := waitForLeaderElection(t, peers2)

	require.Len(t, leaders1, 1)
	require.Len(t, leaders2, 1)

	combinedPeers := append(peers1, peers2...)

	members := make([]discovery.NetworkMember, 0)
	for _, p := range combinedPeers {
		members = append(members, discovery.NetworkMember{
			PKIid: p.id,
		})
	}

	for i, p := range combinedPeers {
		index := i
		gossipFunc := func(args mock.Arguments) {
			msg := args.Get(0).(*pbgossip.GossipMessage)
			for j := range combinedPeers {
				if index == j {
					continue
				}
				combinedPeers[j].msgCh <- msg
			}
		}
		p.On("Gossip", mock.Anything).Run(gossipFunc)
		p.On("Peers").Return(members)
	}

	time.Sleep(testLeaderAliveThreshold * 5)
	findLeaders := waitForLeaderElection(t, combinedPeers)
	require.Len(t, findLeaders, 1)
	require.Equal(t, leaders1[0], findLeaders[0])

	for _, p := range combinedPeers {
		if p.id.String() == findLeaders[0] {
			waitForBoolFunc(t, p.isLeaderFromCallback, true)
			waitForBoolFunc(t, p.isCallbackInvoked, true)
		} else {
			waitForBoolFunc(t, p.isLeaderFromCallback, false)
			if p.id.String() == leaders2[0] {
				waitForBoolFunc(t, p.isCallbackInvoked, true)
			}
		}
	}
}

func TestLeadershipTakeover(t *testing.T) {
	ids := []common.PKIid{
		common.PKIid("p5"),
		common.PKIid("p4"),
		common.PKIid("p3"),
		common.PKIid("p2"),
	}
	peers := createPeers(testStartupGracePeriod+testLeadershipDeclarationInterval, ids...)
	leaders := waitForLeaderElection(t, peers)
	require.Len(t, leaders, 1)
	require.Equal(t, hex.EncodeToString([]byte("p5")), leaders[0])
	peers[0].Stop()
	time.Sleep(testLeadershipDeclarationInterval + testLeaderAliveThreshold*3)
	leaders = waitForLeaderElection(t, peers[1:])
	require.Len(t, leaders, 1)
	require.Equal(t, hex.EncodeToString([]byte("p2")), leaders[0])
}

func TestWaive(t *testing.T) {
	ids := []common.PKIid{
		common.PKIid("p0"),
		common.PKIid("p1"),
		common.PKIid("p2"),
		common.PKIid("p3"),
		common.PKIid("p4"),
		common.PKIid("p5"),
	}

	peers := createPeers(0, ids...)
	leaders := waitForLeaderElection(t, peers)
	require.Len(t, leaders, 1)
	require.Equal(t, hex.EncodeToString([]byte("p0")), leaders[0])
	peers[0].Waive()
	require.True(t, peers[0].isCallbackInvoked())
	require.False(t, peers[0].isLeaderFromCallback())

	peers[0].lock.Lock()
	peers[0].callbackInvoked = false
	peers[0].lock.Unlock()

	peers[0].Waive()
	require.False(t, peers[0].isCallbackInvoked())

	ensureP0isNotLeader := func() bool {
		leaders := waitForLeaderElection(t, peers)
		return len(leaders) == 1 && leaders[0] != hex.EncodeToString([]byte("p0"))
	}

	waitForBoolFunc(t, ensureP0isNotLeader, true)
	time.Sleep(testLeaderAliveThreshold * 2)
	waitForBoolFunc(t, ensureP0isNotLeader, true)
}

func TestWaiveSinglePeer(t *testing.T) {
	peers := createPeers(0, common.PKIid("p0"))
	waitForLeaderElection(t, peers)
	peers[0].Waive()
	require.False(t, peers[0].IsLeader())
	waitForLeaderElection(t, peers)
}

func TestWaiveAllPeers(t *testing.T) {
	ids := []common.PKIid{
		common.PKIid("p0"),
		common.PKIid("p1"),
	}
	peers := createPeers(0, ids...)
	leaders := waitForLeaderElection(t, peers)
	require.Len(t, leaders, 1)
	require.Equal(t, hex.EncodeToString([]byte("p0")), leaders[0])
	peers[0].Waive()
	leaders = waitForLeaderElection(t, peers)
	require.Len(t, leaders, 1)
	require.Equal(t, hex.EncodeToString([]byte("p1")), leaders[0])
	peers[1].Waive()
	leaders = waitForLeaderElection(t, peers)
	require.Len(t, leaders, 1)
	require.Equal(t, hex.EncodeToString([]byte("p0")), leaders[0])
}

func TestPartition(t *testing.T) {
	ids := []common.PKIid{
		common.PKIid("p5"),
		common.PKIid("p4"),
		common.PKIid("p3"),
		common.PKIid("p2"),
		common.PKIid("p1"),
		common.PKIid("p0"),
	}
	peers := createPeers(0, ids...)
	leaders := waitForLeaderElection(t, peers)

	require.Len(t, leaders, 1)
	require.Equal(t, hex.EncodeToString([]byte("p0")), leaders[0])
	waitForBoolFunc(t, peers[len(peers)-1].isLeaderFromCallback, true)

	for _, p := range peers {
		p.On("Peers").Return([]discovery.NetworkMember{})
		p.On("Gossip", mock.Anything)
	}

	time.Sleep(testLeadershipDeclarationInterval + testLeaderAliveThreshold*2)
	leaders = waitForMultipleLeadersElection(t, peers, 6)
	require.Len(t, leaders, 6)
	for _, p := range peers {
		waitForBoolFunc(t, p.isLeaderFromCallback, true)
	}

	for _, p := range peers {
		p.sharedLock.Lock()
		p.mockedMethods = make(map[string]struct{})
		p.callbackInvoked = false
		p.sharedLock.Unlock()
	}

	time.Sleep(testLeadershipDeclarationInterval+testLeaderAliveThreshold*2)
	leaders = waitForLeaderElection(t, peers)
	require.Len(t, leaders, 1)
	require.Equal(t, hex.EncodeToString([]byte("p0")), leaders[0])

	for _, p := range peers {
		if p.id.String() == leaders[0] {
			waitForBoolFunc(t, p.isLeaderFromCallback, true)
		} else {
			waitForBoolFunc(t, p.isLeaderFromCallback, false)
			waitForBoolFunc(t, p.isCallbackInvoked, true)
		}
	}
}

func TestStopLeader(t *testing.T) {
	ids := []common.PKIid{
		common.PKIid("p5"),
		common.PKIid("p4"),
		common.PKIid("p3"),
		common.PKIid("p2"),
		common.PKIid("p1"),
		common.PKIid("p0"),
	}

	peers := createPeers(0, ids...)

	leaders := waitForLeaderElection(t, peers)
	require.Len(t, leaders, 1)

	require.Equal(t, hex.EncodeToString([]byte("p0")), leaders[0])

	peers[len(peers)-1].Waive()

	leaders = waitForLeaderElection(t, peers)
	require.Len(t, leaders, 1)
	require.Equal(t, hex.EncodeToString([]byte("p1")), leaders[0])
	time.Sleep(testLeaderAliveThreshold * 6)
	leaders = waitForLeaderElection(t, peers)
	require.Len(t, leaders, 1)

	require.Equal(t, hex.EncodeToString([]byte("p1")), leaders[0])

	peers[len(peers)-2].Waive()

	leaders = waitForLeaderElection(t, peers)
	require.Len(t, leaders, 1)
	require.Equal(t, hex.EncodeToString([]byte("p0")), leaders[0])
}
