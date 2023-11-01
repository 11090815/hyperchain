package comm

import (
	"context"

	"github.com/11090815/hyperchain/common/metrics"
	"google.golang.org/grpc/stats"
)

var (
	openedConnCounterOpts = metrics.CounterOpts{
		Namespace: "grpc",
		Subsystem: "comm",
		Name:      "conn_opened",
		Help:      "gRPC connections opened. Opened minus closed is the active number of connections.",
	}

	closedConnCounterOpts = metrics.CounterOpts{
		Namespace: "grpc",
		Subsystem: "comm",
		Name:      "conn_closed",
		Help:      "gRPC connections closed. Opened minus closed is the active number of connections.",
	}
)

type ServerStatsHandler struct {
	OpenedConnCounter metrics.Counter
	ClosedConnCounter metrics.Counter
}

func NewServerStatsHandler(p metrics.Provider) *ServerStatsHandler {
	return &ServerStatsHandler{
		OpenedConnCounter: p.NewCounter(openedConnCounterOpts),
		ClosedConnCounter: p.NewCounter(closedConnCounterOpts),
	}
}

// TagRPC 可以为给定的上下文附加一些信息。在 RPC 的其余生命周期中使用的上下文将来自返回的上下文。（这里并没有实现该方法）
func (ssh *ServerStatsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return ctx
}

// HandleRPC 处理 RPC 统计信息。（这里并没有实现该方法）
func (ssh *ServerStatsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {}

// TagConn 可以为给定的上下文附加一些信息。返回的上下文将用于统计处理。对于连接统计处理，HandleConn 中用于此连接的上下文将从返回的上下文中导出。对于 RPC 统计处理：
//   - 在服务器端，用于此连接上所有 RPC 的 HandleRPC 中的上下文将从返回的上下文中导出。
//   - 在客户端，上下文不是从返回的上下文派生的。
//
// （这里并没有实现该方法）
func (ssh *ServerStatsHandler) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	return ctx
}

// HandleConn 处理 Conn 统计信息。统计建立起的连接数量和连接关闭的数量。
func (ssh *ServerStatsHandler) HandleConn(ctx context.Context, s stats.ConnStats) {
	switch s.(type) {
	case *stats.ConnBegin:
		ssh.OpenedConnCounter.Add(1)
	case *stats.ConnEnd:
		ssh.ClosedConnCounter.Add(1)
	}
}
