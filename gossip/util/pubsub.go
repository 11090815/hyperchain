package util

import (
	"fmt"
	"sync"
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/vars"
)

var logger = hlogging.MustGetLogger("pubsub")

const (
	subscriptionBufSize = 50
)

type PubSub struct {
	subscriptions map[string]*Set // topic => subscription(s)
	mutex         *sync.RWMutex
}

func NewPubSub() *PubSub {
	return &PubSub{
		subscriptions: make(map[string]*Set),
		mutex:         &sync.RWMutex{},
	}
}

func (ps *PubSub) Subscribe(topic string, ttl time.Duration) Subscription {
	sub := &subscription{
		topic: topic,
		ttl:   ttl,
		c:     make(chan interface{}, subscriptionBufSize),
	}

	ps.mutex.Lock()
	s, exists := ps.subscriptions[topic]
	if !exists {
		s = NewSet()
		ps.subscriptions[topic] = s
	}
	ps.mutex.Unlock()

	s.Add(sub)
	time.AfterFunc(ttl, func() {
		ps.mutex.Lock()
		defer ps.mutex.Unlock()
		ps.subscriptions[topic].Remove(sub)
		if ps.subscriptions[topic].Size() == 0 {
			delete(ps.subscriptions, topic)
		}
		logger.Debugf("There is a subscription on topic [%s] is expired.", topic)
	})

	return sub
}

func (ps *PubSub) Publish(topic string, item interface{}) error {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()
	s, subscribed := ps.subscriptions[topic]
	if !subscribed {
		return vars.NewPathError(fmt.Sprintf("no subscribers subscribed topic [%s]", topic))
	}

	for _, sub := range s.ToArray() {
		select {
		case sub.(*subscription).c <- item:
		default:
			// 如果缓冲区的空间不够了，我们不会等待
			logger.Debugf("The buffer of subscription on topic [%s] is not enough.", topic)
		}
	}
	return nil
}

// Size 返回所有订阅者的数量。
func (ps *PubSub) Size() int {
	size := 0
	for _, s := range ps.subscriptions {
		size += s.Size()
	}
	return size
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type Subscription interface {
	Listen() (interface{}, error)
}

type subscription struct {
	topic string
	ttl   time.Duration
	c     chan interface{}
}

func (s *subscription) Listen() (interface{}, error) {
	select {
	case <-time.After(s.ttl):
		return nil, vars.NewPathError("timed out")
	case item := <-s.c:
		return item, nil
	}
}
