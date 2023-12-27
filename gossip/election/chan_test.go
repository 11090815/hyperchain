package election

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestChan(t *testing.T) {
	inCh := make(chan int, 2000)
	outCh := make(chan int, 2000)

	record := []int{}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	num := 1000
	go func(n int) {
		for i := 1; i <= n; i++ {
			select {
			case inCh <- i:
				record = append(record, i)
			default:
			}
			time.Sleep(time.Millisecond * time.Duration(r.Intn(10)))

			if i == 250 {
				time.Sleep(time.Second * 10)
			}

			if i == 500 {
				close(inCh)
				return
			}
		}
	}(num)

	time.Sleep(time.Millisecond * 10)

SELECT:
	for {
		select {
		case item, ok := <-inCh:
			if ok {
				outCh <- item
			} else {
				close(outCh)
				break SELECT
			}
		}
	}

	require.Len(t, outCh, 500)
}

func TestSelectBreak(t *testing.T) {
	ch := make(chan int, 1000)
	exit := make(chan struct{})

	isStopped := func() bool {
		select {
		case <-exit:
			return true
		default:
			return false
		}
	}
	go func() {
		timer := time.NewTimer(time.Second * 3)
		for {
			select {
			case i := <-ch:
				if i == 1 {
					break
				}
				fmt.Println(i)
			case <-timer.C:
				close(exit)
			}
		}
	}()

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for !isStopped() {
		select {
		case ch <- r.Intn(3):
			time.Sleep(time.Millisecond * 30)
		default:
		}
	}
}

func TestChanPush(t *testing.T) {
	ch := make(chan struct{}, 1)
	go func() {
		time.Sleep(time.Second)
		<-ch
	}()
	ch <- struct{}{}
	t.Log(len(ch))
}
