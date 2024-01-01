package comm

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestContextTimeout(t *testing.T) {
	ctx := context.Background()
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer func() {
		cancel()
		t.Log("取消了")
	}()

	go doSomething(ctxWithTimeout)

	select {
	case <-ctxWithTimeout.Done():
		fmt.Println("操作超时")
	}
	// time.Sleep(time.Second * 4)
}

func doSomething(ctx context.Context) {
	// 模拟耗时操作
	time.Sleep(3 * time.Second)

	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		fmt.Println("操作被取消")
	default:
		fmt.Println("操作完成")
	}
}
