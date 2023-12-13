package msgstore

import (
	"sync"
	"time"

	"github.com/11090815/hyperchain/gossip/common"
)

// 消息被添加和被删除时触发。
type invalidationTrigger func(message interface{})

type MessageStore interface {
	// 返回的布尔值表示消息存储是否成功。
	Add(msg interface{}) bool

	// 返回的布尔值表示消息是否合法，是否能被存储，实际上就是将给定的消息与存储区里的每个
	// 消息进行一一对比，如果给定的消息在某个已存储的消息面前是无效的，那么此消息就是不合
	// 法的，例如给定的消息是反映节点状态的消息，由于节点状态会随着时间而变化，所以如果给
	// 定的消息比存储区中某个消息旧，说明给定的消息已经过时了，不足以反映节点的当前状态，
	// 那么此时给定的消息就是无效的，或者说是不合法的，不适合再存储到存储区里了。
	CheckValid(msg interface{}) bool

	// 返回当前消息存储区中存储的消息条数（去除掉已过期的消息）。
	Size() int

	// 返回当前存储区中的所有消息（不包含已过期的消息）。
	Get() []interface{}

	// 停止消息存储服务。
	Stop()

	// 根据接收的谓词参数清楚特定的消息。
	Purge(func(interface{}) bool)
}

type messageStoreImpl struct {
	policy            common.MessageReplacingPolicy
	messages          []*msg
	invTrigger        invalidationTrigger
	expiredCount      int
	externalLock      func()                       // 让外部的某个进程暂停
	externalUnlock    func()                       // 取消让外部某个进程暂停
	expireMsgCallback func(expiredMsg interface{}) // 处理一下已过期的消息
	msgTTL            time.Duration                // 消息的生存时间
	doneCh            chan struct{}
	stopOnce          sync.Once
	mutex             sync.RWMutex
}

type msg struct {
	data    interface{}
	created time.Time
	expired bool
}

func NewMessageStore(policy common.MessageReplacingPolicy, trigger invalidationTrigger) MessageStore {
	return newMsgStoreImpl(policy, trigger)
}

func NewMessageStoreExpirable(policy common.MessageReplacingPolicy, trigger invalidationTrigger, msgTTL time.Duration, externalLock func(), externalUnlock func(), externalExpire func(interface{})) MessageStore {
	ms := newMsgStoreImpl(policy, trigger)
	ms.msgTTL = msgTTL

	if externalLock != nil {
		ms.externalLock = externalLock
	}

	if externalUnlock != nil {
		ms.externalUnlock = externalUnlock
	}

	if externalExpire != nil {
		ms.expireMsgCallback = externalExpire
	}

	go ms.expirationRoutine()

	return ms
}

func newMsgStoreImpl(policy common.MessageReplacingPolicy, trigger invalidationTrigger) *messageStoreImpl {
	return &messageStoreImpl{
		policy:     policy,
		messages:   make([]*msg, 0),
		invTrigger: trigger,

		externalLock:      func() {},
		externalUnlock:    func() {},
		expireMsgCallback: func(expiredMsg interface{}) {},
		expiredCount:      0,

		doneCh: make(chan struct{}),
	}
}

func (msi *messageStoreImpl) Add(message interface{}) bool {
	msi.mutex.Lock()
	defer msi.mutex.Unlock()

	// 获取存储区中已存储的消息条数
	m := len(msi.messages)
	for i := 0; i < m; i++ {
		storedMessage := msi.messages[i] // 逐个获取存储区中的消息
		switch msi.policy(message, storedMessage.data) {
		case common.MessageInvalidated:
			return false // 想要被存储的消息被已经存储的消息搞得无效了
		case common.MessageInvalidates:
			msi.invTrigger(storedMessage.data)
			msi.messages = append(msi.messages[:i], msi.messages[i+1:]...) // 想要被存储的消息让已经被存储的消息无效了
			m--
			i--
		}
	}

	msi.messages = append(msi.messages, &msg{data: message, created: time.Now()})
	return true
}

func (msi *messageStoreImpl) Purge(shouldBePurged func(interface{}) bool) {
	msi.mutex.Lock()
	defer msi.mutex.Unlock()

	n := len(msi.messages)
	for i := 0; i < n; i++ {
		if !shouldBePurged(msi.messages[i].data) {
			continue
		}
		msi.invTrigger(msi.messages[i].data)
		msi.messages = append(msi.messages[:i], msi.messages[i+1:]...)
		n--
		i--
	}
}

func (msi *messageStoreImpl) CheckValid(message interface{}) bool {
	msi.mutex.RLock()
	defer msi.mutex.RUnlock()

	for _, storedMessage := range msi.messages {
		if msi.policy(message, storedMessage.data) == common.MessageInvalidated {
			return false
		}
	}

	return true
}

func (msi *messageStoreImpl) Size() int {
	msi.mutex.RLock()
	defer msi.mutex.RUnlock()
	return len(msi.messages) - msi.expiredCount
}

func (msi *messageStoreImpl) Get() []interface{} {
	res := make([]interface{}, 0)

	msi.mutex.RLock()
	defer msi.mutex.RUnlock()

	for _, message := range msi.messages {
		if !message.expired {
			res = append(res, message.data)
		}
	}

	return res
}

func (msi *messageStoreImpl) Stop() {
	msi.stopOnce.Do(func() {
		close(msi.doneCh)
	})
}

func (msi *messageStoreImpl) expireMessages() {
	msi.externalLock() // TODO 为什么在让消息过期的时候，要让外部某个进程暂停
	msi.mutex.Lock()
	defer msi.mutex.Unlock()
	defer msi.externalUnlock()

	n := len(msi.messages)
	for i := 0; i < n; i++ {
		message := msi.messages[i]
		if !message.expired { // 消息过期的标志位还没被设置，但不代表它没过期
			if time.Since(message.created) > msi.msgTTL {
				// 消息被创造至今已经超过了其所被允许的生存时间
				message.expired = true
				msi.expireMsgCallback(message.data)
				msi.expiredCount++
			}
		} else {
			if time.Since(message.created) > (2 * msi.msgTTL) { // 消息被创造至今已经远超于其所被允许的生存时间
				msi.messages = append(msi.messages[:i], msi.messages[i+1:]...)
				n--
				i--
				msi.expiredCount--
			}
		}
	}
}

func (msi *messageStoreImpl) expirationRoutine() {
	for {
		select {
		case <-msi.doneCh:
			return
		case <-time.After(msi.msgTTL / 100):
			msi.expireMessages()
		}
	}
}
