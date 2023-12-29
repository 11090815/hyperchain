package election

import (
	"bytes"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/gossip/util"
)

type LeaderElectionService interface {
	// IsLeader 返回该 peer 是否是 leader。
	IsLeader() bool

	// Stop 停止服务。
	Stop()

	// Waive 方法表明放弃领导权，直到选出新的领导者或超时结束。
	Waive()
}

type leaderElectionServiceImpl struct {
	id           common.PKIid
	proposals    *util.Set
	isLeader     int32
	isWaive      int32
	leaderExists int32
	waiveTimer   *time.Timer
	stopCh       chan struct{}
	stopWg       *sync.WaitGroup
	logger       *hlogging.HyperchainLogger
	callback     leadershipCallback
	config       ElectionConfig
	adapter      LeaderElectionAdapter
	interruptCh  chan struct{}
	sleeping     bool

	mutex *sync.Mutex
}

type ElectionConfig struct {
	// 默认 15 秒
	StartupGracePeriod time.Duration
	// 默认 1 秒
	MembershipSampleInterval time.Duration
	// 默认 10 秒
	LeaderAliveThreshold time.Duration
	// 默认 5 秒
	LeaderElectionDuration time.Duration
}

type leadershipCallback func(isLeader bool)

func noopCallback(bool) {}

const (
	DefaultStartGracePeriod         = 15 * time.Second
	DefaultMembershipSampleInterval = 1 * time.Second
	DefaultLeaderAliveThreshold     = 10 * time.Second
	DefaultLeaderElectionDuration   = 5 * time.Second
)

func NewLeaderElectionService(adapter LeaderElectionAdapter, id common.PKIid, callback leadershipCallback, config ElectionConfig, endpoint string) LeaderElectionService {
	if len(id) == 0 {
		panic("nil id")
	}

	impl := &leaderElectionServiceImpl{
		id:          id,
		proposals:   util.NewSet(),
		adapter:     adapter,
		stopCh:      make(chan struct{}),
		interruptCh: make(chan struct{}, 1),
		logger:      util.GetLogger(util.ElectionLogger, endpoint),
		callback:    noopCallback,
		config:      config,
		mutex:       &sync.Mutex{},
		stopWg:      &sync.WaitGroup{},
	}

	if callback != nil {
		impl.callback = callback
	}

	go impl.start()
	return impl
}

func (impl *leaderElectionServiceImpl) IsLeader() bool {
	return atomic.LoadInt32(&impl.isLeader) == int32(1)
}

func (impl *leaderElectionServiceImpl) Waive() {
	impl.mutex.Lock()
	defer impl.mutex.Unlock()

	// 下面的判断逻辑表明，如果咱之前是 leader，那么就在这次竞选中放弃竞选 leader，将机会留给别人。
	if !impl.IsLeader() || (impl.isWaiving()) {
		return
	}
	// 表明自己已放弃成为 leader
	atomic.StoreInt32(&impl.isWaive, 1)
	// 停止成为 leader
	impl.stopBeingLeader()
	// 清除 leaderExists 标记，因为我们自己可能就是 leader
	atomic.StoreInt32(&impl.leaderExists, 0)
	// 默认情况下，经过 30 秒后清除 isWaive 标记
	impl.waiveTimer = time.AfterFunc(impl.config.LeaderAliveThreshold*6, func() {
		atomic.StoreInt32(&impl.isWaive, 0)
	})
}

func (impl *leaderElectionServiceImpl) Stop() {
	select {
	case <-impl.stopCh:
	default:
		close(impl.stopCh)
		impl.stopWg.Wait()
	}
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

func (impl *leaderElectionServiceImpl) start() {
	impl.stopWg.Add(2)
	go impl.handleMessages()
	impl.waitForMembershipStabilization(impl.config.StartupGracePeriod)
	go impl.run()
}

func (impl *leaderElectionServiceImpl) handleMessages() {
	defer impl.stopWg.Done()
	msgChan := impl.adapter.Accept()
	for {
		select {
		case <-impl.stopCh:
			return
		case msg := <-msgChan:
			if !impl.isAlive(msg.GetLeadershipMsg().PkiId) {
				impl.logger.Debugf("Got message from %s, but it is not in the view.", hex.EncodeToString(msg.GetLeadershipMsg().PkiId))
				break // 这里的 break 表示不会再继续执行本 case 中剩下的代码。
			}
			msgType := "proposal"
			if msg.GetLeadershipMsg().IsDeclaration {
				msgType = "declaration"
			}
			impl.logger.Debugf("Peer %s sent us %s.", hex.EncodeToString(msg.GetLeadershipMsg().PkiId), msgType)

			impl.mutex.Lock()
			if !msg.GetLeadershipMsg().IsDeclaration { // is proposal
				impl.proposals.Add(common.PKIidToStr(msg.GetLeadershipMsg().PkiId))
			} else if msg.GetLeadershipMsg().IsDeclaration {
				atomic.StoreInt32(&impl.leaderExists, 1) // 现在虽然选出了 leader，但是过一段时间后，这个标志位还会被设为 0，到时候还得重新选 leader。
				if impl.sleeping && len(impl.interruptCh) == 0 {
					impl.interruptCh <- struct{}{}
				}
				if bytes.Compare(msg.GetLeadershipMsg().PkiId, impl.id) < 0 && impl.IsLeader() {
					// 对方更适合当 leader，但是如果此时自己是 leader，那么就放弃 leader 的身份。
					impl.logger.Infof("Peer %s is better than me %s to be leader.", hex.EncodeToString(msg.GetLeadershipMsg().PkiId), impl.id.String())
					impl.stopBeingLeader()
				}
			}
			impl.mutex.Unlock()
		}
	}
}

// run 当网络中还没有选出 leader 时，我们会参与竞选，但是如果已经选出了 leader，并且我们在之前放弃了竞选 leader 的话，那么此时，
// 我们就需要恢复我们能够参与竞选 leader 的权利（将 isWaive 标志位置为 0）。如果我们突然成为了 leader，则将我们是 leader 的消
// 息广播出去，否则默认等待 10 秒钟。
func (impl *leaderElectionServiceImpl) run() {
	defer impl.stopWg.Done()
	for !impl.isStopped() {
		if !impl.isLeaderExists() {
			// 还没有 leader，参与竞选 leader
			impl.leaderElection()
		}
		// 如果已经有 leader，且自己放弃竞选，则恢复自己参与竞选的雄心
		if impl.isLeaderExists() && impl.isWaiving() {
			impl.logger.Debug("Stopping waiving.")
			impl.mutex.Lock()
			atomic.StoreInt32(&impl.isWaive, 0)
			impl.waiveTimer.Stop()
			impl.mutex.Unlock()
		}
		if impl.isStopped() {
			return
		}
		if impl.IsLeader() {
			// 可能就在前面的一瞬间，我们在 leaderElection 方法所定义的选举过程中，发现参与竞选的节点里，我的 id 最小，所以我就成为了 leader。
			declaration := impl.adapter.CreateMessage(true)
			impl.adapter.Gossip(declaration)
			impl.adapter.ReportMetrics(true)
			impl.waitForInterrupt(impl.config.LeaderAliveThreshold / 2)
		} else {
			// 如果我不是 leader，那么我就认为目前网络中不存在 leader（将 leaderExists 标志位设为 0），然后等待默认时间 10 秒，再回到 for 循环的开始处，
			// 开始选举新的 leader。
			impl.proposals.Clear()
			atomic.StoreInt32(&impl.leaderExists, 0)
			impl.adapter.ReportMetrics(false)
			select {
			case <-time.After(impl.config.LeaderAliveThreshold):
			case <-impl.stopCh:
			}
		}
	}
}

func (impl *leaderElectionServiceImpl) leaderElection() {
	if impl.isWaiving() {
		// 已放弃竞选 leader
		return
	}

	// 提议自己是 leader
	impl.propose()
	// 收集其他节点的提案
	impl.waitForInterrupt(impl.config.LeaderElectionDuration)
	// 如果 leader 已被选出，则退出选举过程
	if impl.isLeaderExists() {
		impl.logger.Info("Some peer is already a leader.")
		return
	}

	if impl.isWaiving() {
		impl.logger.Debug("Aborting leader election because already waiving.")
		return
	}

	// leader 还未选出，翻看一下是否有节点比自己更适合做 leader
	for _, proposal := range impl.proposals.ToArray() {
		id := proposal.(string)
		idBytes := common.StrToPKIid(id)
		if bytes.Compare(idBytes, impl.id) < 0 {
			impl.logger.Debugf("Peer %s is better than me to be a leader.", id)
			return
		}
	}

	// 目前，在我所收到的提案中，可以看出我的 id 是最小的，那么就让我自己成为 leader。
	impl.logger.Infof("I (%s) becoming a leader.", impl.id.String())
	atomic.StoreInt32(&impl.isLeader, 1)
	impl.callback(true)
	atomic.StoreInt32(&impl.leaderExists, 1)
}

// propose 将自己的 id 包装成 LeadershipMessage 消息，然后广播出去。
//
// 注意：propose 将 LeaderShipMessage 消息结构的 IsDeclaration 设置成 false，所以并不是
// 告诉别人我想当 leader。
func (impl *leaderElectionServiceImpl) propose() {
	proposal := impl.adapter.CreateMessage(false)
	impl.adapter.Gossip(proposal)
}

func (impl *leaderElectionServiceImpl) waitForMembershipStabilization(timeLimit time.Duration) {
	endTime := time.Now().Add(timeLimit)
	viewSize := len(impl.adapter.Peers())

	for !impl.isStopped() {
		time.Sleep(impl.config.MembershipSampleInterval)
		newSize := len(impl.adapter.Peers())
		if newSize == viewSize || time.Now().After(endTime) || impl.isLeaderExists() {
			// 当前成员数量与上一期成员数量一样，或者到时间了，或者已经选出 leader 了，则我们认为网络中的成员达到稳定了
			return
		}
		viewSize = newSize
	}

	impl.logger.Debugf("Membership reach stabilization, found %d peers.", len(impl.adapter.Peers()))
}

// waitForInterrupt 等待直到 interruptCh 通道里有数据为止。
func (impl *leaderElectionServiceImpl) waitForInterrupt(timeout time.Duration) {
	impl.mutex.Lock()
	impl.sleeping = true
	impl.mutex.Unlock()

	select {
	case <-impl.interruptCh: // 当有声明自己是 leader 的消息到来时，会往 interruptCh 通道里添加新的内容
		impl.logger.Info("Someone declares he is leader.")
	case <-impl.stopCh:
	case <-time.After(timeout):
	}

	impl.mutex.Lock()
	impl.sleeping = false
	if len(impl.interruptCh) == 1 {
		<-impl.interruptCh
	}
	impl.mutex.Unlock()
}

func (impl *leaderElectionServiceImpl) stopBeingLeader() {
	impl.logger.Infof("I (%s) stopped being a leader.", impl.id.String())
	atomic.StoreInt32(&impl.isLeader, 0)
	impl.callback(false)
}

func (impl *leaderElectionServiceImpl) isAlive(id common.PKIid) bool {
	for _, peer := range impl.adapter.Peers() {
		if bytes.Equal(peer.PKIid, id) {
			return true
		}
	}
	return false
}

func (impl *leaderElectionServiceImpl) isLeaderExists() bool {
	return atomic.LoadInt32(&impl.leaderExists) == int32(1)
}

func (impl *leaderElectionServiceImpl) isWaiving() bool {
	return atomic.LoadInt32(&impl.isWaive) == int32(1)
}

func (impl *leaderElectionServiceImpl) isStopped() bool {
	select {
	case <-impl.stopCh:
		return true
	default:
		return false
	}
}
