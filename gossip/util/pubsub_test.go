package util

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
	"github.com/stretchr/testify/require"
)

func TestPubSub(t *testing.T) {
	hlogging.ActivateSpec("pubsub=debug")
	ps := NewPubSub()

	sub1 := ps.Subscribe("topic1", time.Second)
	sub2 := ps.Subscribe("topic2", time.Second)
	require.NotNil(t, sub1)
	require.NotNil(t, sub2)

	go func() {
		err := ps.Publish("topic1", &pbgossip.AliveMessage{Identity: []byte("li si")})
		require.NoError(t, err)
	}()

	item, err := sub1.Listen()
	require.NoError(t, err)
	require.True(t, bytes.Equal([]byte("li si"), item.(*pbgossip.AliveMessage).Identity))

	err = ps.Publish("topic3", struct{}{})
	require.Error(t, err)
	fmt.Println(err)

	flag := make(chan struct{})

	go func() {
		time.Sleep(time.Second * 2)
		err = ps.Publish("topic2", struct{}{})
		require.Error(t, err)
		fmt.Println(err)
		close(flag)
	}()

	item, err = sub2.Listen()
	require.Error(t, err)
	fmt.Println(err)
	require.Nil(t, item)
	<-flag

	subs := []Subscription{}
	n := 100

	for i := 0; i < n; i++ {
		subs = append(subs, ps.Subscribe("topic4", time.Second))
	}

	go func() {
		for i := 0; i <= 50; i++ {
			err := ps.Publish("topic4", 100+i)
			require.NoError(t, err)
		}
	}()

	wg := sync.WaitGroup{}
	wg.Add(n)

	for _, sub := range subs {
		go func(s Subscription) {
			time.Sleep(time.Second + time.Millisecond*100)
			require.Equal(t, 0, ps.Size())
			defer wg.Done()
			for i := 0; i < 50; i++ {
				item, err := s.Listen()
				require.NoError(t, err)
				require.Equal(t, 100+i, item)
			}
			item, err = s.Listen()
			require.Nil(t, item)
			require.Error(t, err)
			fmt.Println(err)
		}(sub)
	}
	wg.Wait()
}

type testInst struct {
	store  *Set
	stopCh chan struct{}
}

func newTestInst() *testInst {
	return &testInst{
		store:  NewSet(),
		stopCh: make(chan struct{}),
	}
}

func (inst *testInst) stopped() bool {
	select {
	case <-inst.stopCh:
		return true
	default:
		return false
	}
}

func (inst *testInst) receiveRoutine(sub Subscription, flag chan struct{}) {
	sub_ := sub.(*subscription)
	defer func() {
		fmt.Println("test inst exit...")
		close(flag)
	}()

	// successful test:
	for {
		select {
		case item := <-sub_.c:
			fmt.Println("get item:", item)
		case <-inst.stopCh:
			return
		}
	}

	// failure test:
	// for !inst.stopped() {
	// 	select {
	// 	case item := <-sub_.c:
	// 		fmt.Println("get item:", item)
	// 	}
	// }
}

func TestQuit(t *testing.T) {
	pubsub := NewPubSub()
	inst := newTestInst()
	sub := pubsub.Subscribe("test", time.Millisecond*20)

	flag := make(chan struct{})
	go inst.receiveRoutine(sub, flag)

	for i := 0; i < 10; i++ {
		pubsub.Publish("test", i)
		time.Sleep(time.Millisecond * 10)
		if i == 5 {
			close(inst.stopCh)
			<-inst.stopCh
		}
	}
	<-flag
}
