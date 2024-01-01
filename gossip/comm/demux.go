package comm

import (
	"sync"

	"github.com/11090815/hyperchain/gossip/common"
)

// ChannelDeMultiplexer 是一个通道多路复用器，可以注册通道（AddChannel），同时可以根据注册时
// 定义的谓词（common.MessageAcceptor）将消息发送到对应通道（DeMultiplex）。
type ChannelDeMultiplexer struct {
	mutex           *sync.Mutex
	stopCh          chan struct{}
	deMuxInProgress sync.WaitGroup
	channels        []*channel
}

type channel struct {
	pred common.MessageAcceptor
	ch   chan<- interface{}
}

func NewChannelDeMultiplexer() *ChannelDeMultiplexer {
	return &ChannelDeMultiplexer{
		mutex:  &sync.Mutex{},
		stopCh: make(chan struct{}),
	}
}

// AddChannel 方法用于向多路复用器注册一个通道。如果多路复用器已经停止（isStopped() 返回 true），
// 则返回一个被关闭的通道，以防止外部接收者一直等待。否则，创建一个带有缓冲区的通道（bidirectionalCh），
// 将其注册到 channels 切片中，并返回该通道。
func (cdm *ChannelDeMultiplexer) AddChannel(pred common.MessageAcceptor) <-chan interface{} {
	if cdm.isStopped() {
		ch := make(chan interface{})
		close(ch)
		// 返回一个被关闭的通道，防止外部接收者苦苦等待
		return ch
	}

	bidirectionalCh := make(chan interface{}, 10)
	ch := &channel{ch: bidirectionalCh, pred: pred}
	cdm.mutex.Lock()
	cdm.channels = append(cdm.channels, ch)
	cdm.mutex.Unlock()
	return bidirectionalCh
}

// DeMultiplex 方法用于接收一个消息，并根据注册的谓词将消息发送到相应的通道。如果多路复用器已
// 经停止（isStopped() 返回 true），则直接返回。否则，遍历 channels 切片，对每个通道，如果谓词判
// 断该消息应该发送到该通道，则将消息发送到通道的 ch 通道中。
func (cdm *ChannelDeMultiplexer) DeMultiplex(msg interface{}) {
	if cdm.isStopped() {
		return
	}

	cdm.mutex.Lock()
	channels := cdm.channels
	cdm.deMuxInProgress.Add(1)
	cdm.mutex.Unlock()

	for _, ch := range channels {
		if ch.pred(msg) {
			select {
			case <-cdm.stopCh:
				cdm.deMuxInProgress.Done()
				return
			case ch.ch <- msg:
			}
		}
	}
	cdm.deMuxInProgress.Done()
}

// Stop 方法用于停止多路复用器的操作。首先，检查 stopCh 通道是否已经关闭，如果已经关闭，则直接返回。否则，
// 关闭 stopCh 通道，等待所有的 DeMultiplex 调用完成，然后锁定互斥锁，关闭所有已注册通道的 ch 通道，并清
// 空 channels 切片。
func (cdm *ChannelDeMultiplexer) Stop() {
	select {
	case <-cdm.stopCh:
		return
	default:
		close(cdm.stopCh)
		cdm.deMuxInProgress.Wait()
		cdm.mutex.Lock()
		for _, ch := range cdm.channels {
			close(ch.ch)
		}
		cdm.channels = nil
		cdm.mutex.Unlock()
	}
}

func (cdm *ChannelDeMultiplexer) isStopped() bool {
	select {
	case <-cdm.stopCh:
		return true
	default:
		return false
	}
}
