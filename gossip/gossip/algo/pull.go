package algo

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/gossip/util"
)

/*
	1. 启动者向一组远程对等节点发送带有特定 NONCE 的 Hello 消息；
	2. 每个远程对等节点响应其消息的摘要并返回该 NONCE；
	3. 启动者检查接收到的 NONCE 的有效性，聚合摘要，并创建一个包含要从每个远程对等节点接收的特定项目 ID 的请求，然后将每个请求发送给对应的对等节点；
	4. 每个对等节点返回包含被请求的项目（如果它仍然拥有这些项目）和 NONCE 的响应。

	发起者                                                        其他 peer
	  o     ------------------ Hello <NONCE> ------------------>      o
	 /|\    <----------- Digest <[3,5,8,...], NONCE> -----------     /|\
	  |     --------------- Request <[3,8], NONCE> ------------>      |
	 / \    <-------- Response <[item3,item8], NONCE> ----------     / \
*/

const (
	/*
		一开始，启动者向一组远程 peer 节点发送 hello 消息（针对不同的 peer 节点，启动者会在 hello 消息中放置不同的 nonce），接着启动者会设置一个等待 digest 消息的超时时间，这个
		超时时间一到，启动者就会处理在超时时间内收到的 digests，然后构造 request 消息，向其他 peer 节点发送 request 消息，默认情况下，等待 digest 消息的超时时间是 1 秒。

		收到 hello 消息的 peer 节点，会将 nonce 值暂存在本地，然后设置等待 request 消息的超时时间，这个超时时间一过，peer 节点就会将暂存在本地的 nonce 给删除掉，一旦删除掉，后续，
		启动者如果再基于该 nonce 向 peer 节点发送 request 消息，则会被 peer 节点忽视。默认情况下，peer 节点设置的等待 request 消息的超时时间是 1.5 秒。接着 peer 节点会将存储在
		本地状态机中的值逐一取出，在这里我们把这些值看成是 digest，hello 消息中不仅包含 nonce，其实还包含一个 context，一般情况下，context 代表发送 hello 消息的发送者地址（或姓名），
		即启动者的地址（或姓名），peer 节点利用摘要过滤器 DigestFilter，逐一过滤存储在本地状态机中的 digest。注意观察摘要过滤器的定义，我们可以发现，摘要过滤器它是一个返回值是函数的
		函数，我们将 DigestFilter 视为母函数，DigestFilter 的返回值视为子函数，母函数的入参是 interface{}，参数名就叫 context，因此，我们不难猜出母函数返回的子函数应当与 hello 消
		息中包含的 context 相关，也就是与启动者相关，而子函数的入参是摘要值，所以摘要过滤器会将哪些摘要值过滤出来可能取决于启动者的身份。

		收到 digest 消息的启动者，会将 digest 逐一存储到本地，并建立 digest 与发送者之间的联系，即启动者需要知道每个 digest 是由哪些 peer 节点发送的，之所以是 “哪些”，是因为不同的
		peer 节点可能会发送相同的 digest。当等待 digest 的超时时间一过，则启动者会根据在超时时间内收到的 digest 构建一个 request 消息，并且此时启动者将不会再接收新的 digest 消息。、
		request 构造规则可以通过举一个例子来说明：例如有两个 peer 节点：p1 和 p2，p1 给启动者发送的 digests 是 [1 2 3]，p2 给启动者发送的 digests 是 [2 4 3]，那么启动者收到的
		digests 经过去重处理后是 [1 2 3 4]，digest 与发送者之间的联系如下：
			1 => {p1}
			2 => {p1, p2}
			3 => {p1, p2}
			4 => {p2}
		启动者会随机构造 2 个 request 消息，它首先遍历 [1 2 3 4]，首先是 1 这个 digest，它仅由 p1 发送，所以启动者构造 req1{[1], p1}；接着遍历到 2，它由 p1 和 p2 发送，启动者从 p1
		和p2 中随机选一个，例如选到 p1，那么启动者更新 req1{[1, 2], p1}；接着遍历到 3，它由 p1 和 p2 发送，启动者从 p1 和 p2 中随机选一个，例如选到 p2，那么启动者构造 req2{[3], p1}；
		最后遍历到 4，它仅由 p2 发送，因此，启动者更新 req2{[3, 4], p2}。启动者分别将 req1 和 req2 发送给 p1 和 p2，并进入等待 response 消息的超时时间内，一旦超时时间一过，则启动者会
		结束本次 pull 进程。

		收到 request 消息的 peer 节点，会解析 request 消息，得到其中的 digests，然后逐一提取其中的 digest，并判断本地状态机中是否有存储该 digest，其次还会根据 摘要过滤器 DigestFilter
		判断此 digest 能不能发送给启动者，如果本地状态机存有该 digest 且过滤器判断结果是可以发送，那么 peer 节点就会构造 response 消息，将能发送的 digest（item）发送给启动者。

		收到 response 消息的启动者，会将 response 消息中的 items 存储到本地状态机中。

		从上面的过程可以看出，DigestWaitTime 必须小于 RequestWaitTime，如果 DigestWaitTime 大于或等于 RequestWaitTime，那么 peer 节点会率先因为超时（RequestWaitTime）将暂存
		在本地的 nonce 删除掉。之后启动者才因为超时（DigestWaitTime）向 peer 节点发送 request 消息，这样的话就已经迟了，peer 节点会因为在本地找不到 request 消息中的 nonce 而忽
		视掉启动者发送来的 request。而 ResponseWaitTime 的大小则与 DigestWaitTime 和 RequestWaitTime 无关，它主要取决于网络质量的好坏。
	*/
	DigestWaitTime   = 1000 * time.Millisecond
	RequestWaitTime  = 1500 * time.Millisecond
	ResponseWaitTime = 2000 * time.Millisecond
)

var logger = hlogging.MustGetLogger("gossip.pull")

// DigestFilter 会根据消息的上下文过滤出来要发送给启动者的摘要。
type DigestFilter func(context interface{}) func(digestItem string) bool

type PullAdapter interface {
	SelectPeers() []string

	Hello(dest string, nonce uint64)

	// context 可能代表的是 digest 消息的接收者地址
	SendDigest(digest []string, nonce uint64, context interface{})

	SendReq(dest string, items []string, nonce uint64)

	// context 可能代表的是 response 消息的接收者地址
	SendRes(items []string, context interface{}, nonce uint64)
}

type PullEngince struct {
	PullAdapter
	PullEngineConfig
	stopFlag           int32
	state              *util.Set           // TODO 存的到底是 digest 还是 item？
	item2owners        map[string][]string // item 实际上就是摘要，从 OnDigest 方法中可以看出
	peers2nonces       map[string]uint64   // 记录给 peer 节点最后发送了什么 nonce，给每个节点发送的 nonce 都是独一无二的
	nonces2peers       map[uint64]string   // 记录将 nonce 发送给了哪个 peer 节点，给每个节点发送的 nonce 都是独一无二的
	acceptingDigests   int32
	acceptingResponses int32
	outgoingNONCES     *util.Set
	incomingNONCES     *util.Set
	digestFilter       DigestFilter
	mutex              *sync.Mutex
}

type PullEngineConfig struct {
	DigestWaitTime   time.Duration
	RequestWaitTime  time.Duration
	ResponseWaitTime time.Duration
}

func NewPullEngineWithFilter(participant PullAdapter, sleepTime time.Duration, df DigestFilter, config PullEngineConfig) *PullEngince {
	pe := &PullEngince{
		PullAdapter:        participant,
		PullEngineConfig:   config,
		stopFlag:           0,
		state:              util.NewSet(),
		item2owners:        make(map[string][]string),
		peers2nonces:       make(map[string]uint64),
		nonces2peers:       make(map[uint64]string),
		acceptingDigests:   0,
		acceptingResponses: 0,
		outgoingNONCES:     util.NewSet(),
		incomingNONCES:     util.NewSet(),
		digestFilter:       df,
		mutex:              &sync.Mutex{},
	}

	go func() {
		for !pe.toDie() {
			time.Sleep(sleepTime)
			if pe.toDie() {
				return
			}
			pe.initiatePull()
		}
	}()

	return pe
}

func NewPullEngine(participant PullAdapter, sleepTime time.Duration, config PullEngineConfig) *PullEngince {
	var df DigestFilter = func(context interface{}) func(digestItem string) bool {
		return func(digestItem string) bool {
			return true
		}
	}

	return NewPullEngineWithFilter(participant, sleepTime, df, config)
}

// OnHello 告诉 PullEngine 有一条 hello 消息到了，将自己本地存储的 digest 发送给 hello 消息的发送者。
func (pe *PullEngince) OnHello(nonce uint64, context interface{}) {
	logger.Debugf("Receive hello message with nonce [%d] from [%s].", nonce, context)
	pe.incomingNONCES.Add(nonce)

	time.AfterFunc(pe.RequestWaitTime, func() {
		// TODO 为什么等待请求的时间到了后，要把 nonce 删掉呢
		pe.incomingNONCES.Remove(nonce)
		logger.Debugf("Request wait time [%v] timeout, remove nonce [%d] from incoming nonces cache.", pe.RequestWaitTime, nonce)
	})

	items := pe.state.ToArray()

	var digests []string
	filter := pe.digestFilter(context)

	for _, item := range items {
		digest := item.(string)
		if !filter(digest) {
			continue
		}
		digests = append(digests, digest)
	}

	if len(digests) == 0 {
		return
	}
	pe.SendDigest(digests, nonce, context)
	logger.Debugf("Send digest message with nonce [%d] and digests [%v] to [%s].", nonce, digests, context)
}

// OnDigest 告诉 PullEngine 有一个 digest 到了，处理远程对等节点返回的摘要信息，并将相关的项目添加到PullEngine的状态中。
func (pe *PullEngince) OnDigest(digests []string, nonce uint64, context interface{}) {
	if !pe.isAcceptingDigests() || !pe.outgoingNONCES.Exists(nonce) {
		// 如果正在处理接收到来的摘要信息，或者并未启动 pull，再或者发送过来的 nonce 不存在，则不会接收新到来的摘要信息
		if !pe.isAcceptingDigests() {
			logger.Warnf("It is not a good time to receive digest message.")
		} else if !pe.outgoingNONCES.Exists(nonce) {
			logger.Warnf("Ignore the arrived digest message, because i haven't sent a hello message with nonce [%d] to any other peers.", nonce)
		}
		return
	}

	logger.Debugf("Receive digest message with nonce [%d] and digests [%v] from [%s].", nonce, digests, context)

	pe.mutex.Lock()
	defer pe.mutex.Unlock()

	for _, digest := range digests {
		// 遍历我收到的所有摘要
		if pe.state.Exists(digest) {
			// 如果我已经有了这条摘要信息，则跳过不处理
			continue
		}

		if _, exists := pe.item2owners[digest]; !exists {
			// 如果没有节点给我发送过这个摘要，那么我就会为这个摘要开辟一个空间，用来存储给我发送此条摘要信息的节点
			pe.item2owners[digest] = make([]string, 0)
		}

		// 发回此 nonce 的 peer 节点，即是在 Hello 阶段从启动者处收到 nonce 的 peer 节点
		pe.item2owners[digest] = append(pe.item2owners[digest], pe.nonces2peers[nonce])
	}
}

// OnReq 告诉 PullEngine 有一个 request 到了，将 OnReq 方法的第一个入参发送给发送 request 的 peer 节点。
func (pe *PullEngince) OnReq(items []string, nonce uint64, context interface{}) {
	if !pe.incomingNONCES.Exists(nonce) {
		logger.Warnf("Ignore the arrived request message, because i haven't received a hello message with nonce [%d] from any other peers.", nonce)
		return
	}

	logger.Debugf("Receive request message with nonce [%d] and items [%v] from [%s].", nonce, items, context)

	pe.mutex.Lock()
	defer pe.mutex.Unlock()

	filter := pe.digestFilter(context)
	var items2Send []string

	for _, item := range items {
		if pe.state.Exists(item) && filter(item) {
			items2Send = append(items2Send, item)
		}
	}

	if len(items2Send) == 0 {
		return
	}

	go pe.SendRes(items2Send, context, nonce)
	logger.Debugf("Send response message with nonce [%d] and items [%v] to [%s].", nonce, items2Send, context)
}

// OnRes 提醒 PullEngine 有一个 response 消息到了，将 OnRes 的第一个入参存储到本地 state 中。
func (pe *PullEngince) OnRes(items []string, nonce uint64) {
	if !pe.outgoingNONCES.Exists(nonce) || !pe.isAcceptingResponses() {
		if !pe.outgoingNONCES.Exists(nonce) {
			logger.Warnf("Ignore the arrived response message, because i haven't sent a hello message with nonce [%d] to any other peers.", nonce)
		} else if !pe.isAcceptingResponses() {
			logger.Warnf("It is not a good time to receive response message.")
		}
		return
	}

	logger.Debugf("Receive response message with nonce [%d] and items [%v].", nonce, items)

	pe.Add(items...)
}

func (pe *PullEngince) Add(seqs ...string) {
	for _, seq := range seqs {
		pe.state.Add(seq)
	}
}

func (pe *PullEngince) Remove(seqs ...string) {
	for _, seq := range seqs {
		pe.state.Remove(seq)
	}
}

func (pe *PullEngince) Stop() {
	atomic.StoreInt32(&pe.stopFlag, 1)
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

// initiatePull 这个方法会一直不停的循环被执行。
func (pe *PullEngince) initiatePull() {
	pe.mutex.Lock()
	defer pe.mutex.Unlock()

	pe.acceptDigests()
	for _, peer := range pe.SelectPeers() {
		nonce := pe.newNONCE()
		pe.outgoingNONCES.Add(nonce)
		pe.peers2nonces[peer] = nonce // 记录给 peer 节点最后发送了什么 nonce
		pe.nonces2peers[nonce] = peer // 记录将 nonce 发送给了哪个 peer 节点
		pe.Hello(peer, nonce)
		logger.Debugf("Send hello message with nonce [%d] to [%s].", nonce, peer)
	}

	time.AfterFunc(pe.DigestWaitTime, func() {
		// 等接收 digests 的时间超时了，我们开始处理到来的 digests
		pe.processIncomingDigests()
	})
}

func (pe *PullEngince) processIncomingDigests() {
	pe.ignoreDigests() // 正在处理到来的摘要信息时，会拒绝接收新到来的的摘要信息。

	pe.mutex.Lock()
	defer pe.mutex.Unlock()

	requestMapping := make(map[string][]string)

	for item, owners := range pe.item2owners {
		// 随机选择一个 owner
		owner := owners[util.RandomIntn(len(owners))]
		if _, exists := requestMapping[owner]; !exists {
			requestMapping[owner] = make([]string, 0)
		}
		// 确保请求的 item 都来自于收到的 digest 消息，并且确保不会向不同的节点发送相同的 item 请求。
		requestMapping[owner] = append(requestMapping[owner], item)
	}

	pe.acceptResponses()

	for owner, seqsToRequest := range requestMapping {
		// 我又向 owner 发送一遍请求相同 item 的请求
		pe.SendReq(owner, seqsToRequest, pe.peers2nonces[owner])
		logger.Debugf("Send request message with nonce [%d] and seqs [%v] to [%s].", pe.peers2nonces[owner], seqsToRequest, owner)
	}

	time.AfterFunc(pe.ResponseWaitTime, pe.endPull)
}

func (pe *PullEngince) endPull() {
	pe.mutex.Lock()
	defer pe.mutex.Unlock()

	atomic.StoreInt32(&pe.acceptingResponses, 0)
	pe.outgoingNONCES.Clear()

	pe.item2owners = make(map[string][]string)
	pe.peers2nonces = make(map[string]uint64)
	pe.nonces2peers = make(map[uint64]string)

	logger.Debugf("End pull.")
}

func (pe *PullEngince) ignoreDigests() {
	atomic.StoreInt32(&pe.acceptingDigests, 0)
}

func (pe *PullEngince) acceptDigests() {
	atomic.StoreInt32(&pe.acceptingDigests, 1)
}

func (pe *PullEngince) isAcceptingDigests() bool {
	return atomic.LoadInt32(&pe.acceptingDigests) == 1
}

func (pe *PullEngince) acceptResponses() {
	atomic.StoreInt32(&pe.acceptingResponses, 1)
}

func (pe *PullEngince) isAcceptingResponses() bool {
	return atomic.LoadInt32(&pe.acceptingResponses) == 1
}

func (pe *PullEngince) toDie() bool {
	return atomic.LoadInt32(&pe.stopFlag) == 1
}

func (pe *PullEngince) newNONCE() uint64 {
	n := uint64(0)
	for {
		n = util.RandomUint64()
		if !pe.outgoingNONCES.Exists(n) {
			return n
		}
	}
}
