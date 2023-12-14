package algo

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/gossip/util"
	"github.com/stretchr/testify/require"
)

type messageHook func(interface{})

type pullInstance struct {
	msgHooks          []messageHook
	peers             map[string]*pullInstance
	name              string
	nextPeerSelection []string
	msgQueue          chan interface{}
	stopCh            chan struct{}
	mutex             *sync.Mutex
	*PullEngince
}

type helloMsg struct {
	nonce  uint64
	source string
}

type digestMsg struct {
	nonce   uint64
	digests []string
	source  string
}

type reqMsg struct {
	items  []string
	nonce  uint64
	source string
}

type resMsg struct {
	items []string
	nonce uint64
}

func newPullInstance(name string, peers map[string]*pullInstance) *pullInstance {
	inst := &pullInstance{
		msgHooks:          make([]messageHook, 0),
		peers:             peers,
		name:              name,
		nextPeerSelection: make([]string, 0),
		msgQueue:          make(chan interface{}, 100),
		stopCh:            make(chan struct{}),
		mutex:             &sync.Mutex{},
	}

	config := PullEngineConfig{
		DigestWaitTime:   100 * time.Millisecond,
		RequestWaitTime:  200 * time.Millisecond,
		ResponseWaitTime: 200 * time.Millisecond,
	}

	inst.PullEngince = NewPullEngine(inst, 500*time.Millisecond, config)

	peers[name] = inst

	go func() {
		for {
			select {
			case <-inst.stopCh:
				return
			case m := <-inst.msgQueue:
				inst.handleMessage(m)
			}
		}
	}()

	return inst
}

func (inst *pullInstance) hook(hook messageHook) {
	inst.mutex.Lock()
	defer inst.mutex.Unlock()
	inst.msgHooks = append(inst.msgHooks, hook)
}

func (inst *pullInstance) handleMessage(m interface{}) {
	inst.mutex.Lock()
	for _, hook := range inst.msgHooks {
		hook(m)
	}
	inst.mutex.Unlock()

	if hello, ok := m.(*helloMsg); ok {
		inst.OnHello(hello.nonce, hello.source)
		return
	}

	if digest, ok := m.(*digestMsg); ok {
		inst.OnDigest(digest.digests, digest.nonce, digest.source)
		return
	}

	if req, ok := m.(*reqMsg); ok {
		inst.OnReq(req.items, req.nonce, req.source)
		return
	}

	if res, ok := m.(*resMsg); ok {
		inst.OnRes(res.items, res.nonce)
		return
	}
}

func (inst *pullInstance) stop() {
	close(inst.stopCh)
	inst.Stop()
}

func (inst *pullInstance) setNextPeerSelection(selection []string) {
	inst.mutex.Lock()
	defer inst.mutex.Unlock()
	inst.nextPeerSelection = selection
}

func (inst *pullInstance) SelectPeers() []string {
	inst.mutex.Lock()
	inst.mutex.Unlock()
	return inst.nextPeerSelection
}

func (inst *pullInstance) Hello(dest string, nonce uint64) {
	inst.peers[dest].msgQueue <- &helloMsg{nonce: nonce, source: inst.name}
}

func (inst *pullInstance) SendDigest(digests []string, nonce uint64, context interface{}) {
	inst.peers[context.(string)].msgQueue <- &digestMsg{nonce: nonce, digests: digests, source: inst.name}
}

func (inst *pullInstance) SendReq(dest string, items []string, nonce uint64) {
	inst.peers[dest].msgQueue <- &reqMsg{nonce: nonce, source: inst.name, items: items}
}

func (inst *pullInstance) SendRes(items []string, context interface{}, nonce uint64) {
	inst.peers[context.(string)].msgQueue <- &resMsg{items: items, nonce: nonce}
}

func init() {
	hlogging.Init(hlogging.Config{
		Format:  hlogging.ShortFuncFormat,
		LogSpec: "gossip.pull=debug",
	})
}

func TestPullEngineAdd(t *testing.T) {
	peers := make(map[string]*pullInstance)
	inst1 := newPullInstance("p1", peers)
	defer inst1.stop()
	inst1.Add("0")
	inst1.Add("0")
	require.True(t, inst1.state.Exists("0"))
}

func TestPullEngineRemove(t *testing.T) {
	peers := make(map[string]*pullInstance)
	inst1 := newPullInstance("p1", peers)
	defer inst1.stop()
	inst1.Add("0")
	require.True(t, inst1.state.Exists("0"))
	inst1.Remove("0")
	require.False(t, inst1.state.Exists("0"))
	inst1.Remove("0")
	require.False(t, inst1.state.Exists("0"))
}

func TestPullEnginceStop(t *testing.T) {
	peers := make(map[string]*pullInstance)
	inst1 := newPullInstance("p1", peers)
	inst2 := newPullInstance("p2", peers)
	defer inst2.stop()
	inst2.setNextPeerSelection([]string{"p1"})
	go func() {
		for i := 0; i < 100; i++ {
			inst1.Add(strconv.Itoa(i))
			time.Sleep(10 * time.Millisecond)
		}
	}()

	time.Sleep(time.Millisecond * 800)
	len1 := len(inst2.state.ToArray())
	inst1.stop()
	time.Sleep(800 * time.Millisecond)
	len2 := len(inst2.state.ToArray())
	t.Log(len1, len2)
	require.Equal(t, len1, len2)
}

func TestPullEngineAll2AllWithIncrementalSpawning(t *testing.T) {
	instanceCount := 4
	peers := make(map[string]*pullInstance)

	for i := 0; i < instanceCount; i++ {
		inst := newPullInstance(fmt.Sprintf("p%d", i+1), peers)
		inst.Add(strconv.Itoa(i + 1))
		time.Sleep(50 * time.Millisecond)
	}
	for i := 0; i < instanceCount; i++ {
		peerID := fmt.Sprintf("p%d", i+1)
		peers[peerID].setNextPeerSelection(keySet(peerID, peers))
	}
	time.Sleep(4000 * time.Millisecond)

	for i := 0; i < instanceCount; i++ {
		peerID := fmt.Sprintf("p%d", i+1)
		require.Equal(t, instanceCount, len(peers[peerID].state.ToArray()))
	}
}

func TestPullEngineSelectiveUpdates(t *testing.T) {
	peers := make(map[string]*pullInstance)
	inst1 := newPullInstance("p1", peers)
	inst2 := newPullInstance("p2", peers)
	defer inst1.stop()
	defer inst2.stop()

	inst1.Add("1", "3")
	inst2.Add("0", "1", "2", "3")

	inst1.hook(func(i interface{}) {
		if digest, ok := i.(*digestMsg); ok {
			require.True(t, util.IndexInSlice(digest.digests, "0", Strcmp) != -1)
			require.True(t, util.IndexInSlice(digest.digests, "1", Strcmp) != -1)
			require.True(t, util.IndexInSlice(digest.digests, "2", Strcmp) != -1)
			require.True(t, util.IndexInSlice(digest.digests, "3", Strcmp) != -1)
		}
	})

	inst2.hook(func(i interface{}) {
		if req, ok := i.(*reqMsg); ok {
			require.True(t, util.IndexInSlice(req.items, "0", Strcmp) != -1)
			require.True(t, util.IndexInSlice(req.items, "1", Strcmp) == -1)
			require.True(t, util.IndexInSlice(req.items, "2", Strcmp) != -1)
			require.True(t, util.IndexInSlice(req.items, "3", Strcmp) == -1)
		}
	})

	inst1.hook(func(i interface{}) {
		if res, ok := i.(*resMsg); ok {
			require.True(t, util.IndexInSlice(res.items, "0", Strcmp) != -1)
			require.True(t, util.IndexInSlice(res.items, "1", Strcmp) == -1)
			require.True(t, util.IndexInSlice(res.items, "2", Strcmp) != -1)
			require.True(t, util.IndexInSlice(res.items, "3", Strcmp) == -1)
		}
	})

	inst1.setNextPeerSelection([]string{"p2"})

	time.Sleep(time.Second * 2)
	require.Equal(t, len(inst1.state.ToArray()), len(inst2.state.ToArray()))
}

func TestByzantineResponder(t *testing.T) {
	peers := make(map[string]*pullInstance)
	inst1 := newPullInstance("p1", peers)
	inst2 := newPullInstance("p2", peers)
	inst3 := newPullInstance("p3", peers)
	defer inst1.stop()
	defer inst2.stop()
	defer inst3.stop()

	var receivedDigestFromInst3 int32

	inst2.Add("1", "2", "3")
	inst3.Add("1", "6", "7")

	inst2.hook(func(i interface{}) {
		if _, ok := i.(*helloMsg); ok {
			inst3.SendDigest([]string{"5", "6", "7"}, 0, "p1") // 给 p1 发送 digest
		}
	})

	inst1.hook(func(i interface{}) {
		if digest, ok := i.(*digestMsg); ok {
			if digest.source == "p3" {
				atomic.StoreInt32(&receivedDigestFromInst3, 1)
				time.AfterFunc(time.Millisecond*150, func() {
					inst3.SendRes([]string{"5", "6", "7"}, "p1", 0)
				})
			}
		}

		if res, ok := i.(*resMsg); ok {
			if util.IndexInSlice(res.items, "6", Strcmp) != -1 {
				require.Equal(t, int32(1), atomic.LoadInt32(&inst1.acceptingResponses))
			}
		}
	})

	inst1.setNextPeerSelection([]string{"p2"})
	time.Sleep(time.Second)

	require.Equal(t, int32(1), atomic.LoadInt32(&receivedDigestFromInst3), "inst1 hasn't received a digest from inst3")

	require.True(t, util.IndexInSlice(inst1.state.ToArray(), "1", Strcmp) != -1)
	require.True(t, util.IndexInSlice(inst1.state.ToArray(), "2", Strcmp) != -1)
	require.True(t, util.IndexInSlice(inst1.state.ToArray(), "3", Strcmp) != -1)

	require.True(t, util.IndexInSlice(inst1.state.ToArray(), "5", Strcmp) == -1)
	require.True(t, util.IndexInSlice(inst1.state.ToArray(), "6", Strcmp) == -1)
	require.True(t, util.IndexInSlice(inst1.state.ToArray(), "7", Strcmp) == -1)
}

func Strcmp(a interface{}, b interface{}) bool {
	return a.(string) == b.(string)
}

func keySet(selfPeer string, m map[string]*pullInstance) []string {
	peers := make([]string, len(m)-1)
	i := 0
	for peerID := range m {
		if selfPeer == peerID {
			continue
		}
		peers[i] = peerID
		i++
	}
	return peers
}
