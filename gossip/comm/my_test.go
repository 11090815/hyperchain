package comm

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/11090815/hyperchain/gossip/protoext"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
	"github.com/11090815/hyperchain/vars"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

type client struct {
	cl     pbgossip.GossipClient
	stream pbgossip.Gossip_GossipStreamClient
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type server struct {
	srv *grpc.Server
	// inCh chan *pbgossip.Envelope
}

func (s *server) Ping(context.Context, *pbgossip.Empty) (*pbgossip.Empty, error) {
	return &pbgossip.Empty{}, nil
}

func (s *server) GossipStream(stream pbgossip.Gossip_GossipStreamServer) error {
	for {
		envelope, err := stream.Recv()
		if err != nil {
			return vars.NewPathError(err.Error())
		}
		stream.Send(envelope)
	}
}

func createClient(endpoint string, timeout time.Duration) (*client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	clientConn, err := grpc.DialContext(ctx, endpoint, grpc.WithInsecure())
	if err != nil {
		return nil, vars.NewPathError(err.Error())
	}

	cl := pbgossip.NewGossipClient(clientConn)
	stream, err := cl.GossipStream(context.Background())
	return &client{
		cl:     cl,
		stream: stream,
	}, err
}

func createServer(addr string) (*server, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, vars.NewPathError(err.Error())
	}

	srv := grpc.NewServer()
	go srv.Serve(listener)
	s := &server{srv: srv}
	pbgossip.RegisterGossipServer(srv, s)
	return s, nil
}

func TestCommon(t *testing.T) {
	s, err := createServer(":2048")
	require.NoError(t, err)
	require.NotNil(t, s)

	c, err := createClient("localhost:2048", time.Second)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = c.cl.Ping(ctx, &pbgossip.Empty{})
	require.NoError(t, err)

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	stream, err := c.cl.GossipStream(ctx)
	require.NoError(t, err)

	inCh := make(chan *pbgossip.Envelope, 1)

	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				fmt.Println("err:", err.Error())
				return
			}
			inCh <- msg
		}
	}()

	msg, _ := protoext.NoopSign(&pbgossip.GossipMessage{
		Tag:   pbgossip.GossipMessage_EMPTY,
		Nonce: 123,
		Content: &pbgossip.GossipMessage_Conn{
			Conn: &pbgossip.ConnEstablish{
				PkiId: []byte("localhost"),
			},
		},
	})
	stream.Send(msg.Envelope)
	received := <-inCh
	fmt.Println(received)

	stream.Send(msg.Envelope)
	received = <-inCh
	fmt.Println(received)
}

func TestPeerExtractAddress(t *testing.T) {
	listener, err := net.Listen("tcp", ":2048")
	require.NoError(t, err)
	defer listener.Close()

	srv := grpc.NewServer()
	go srv.Serve(listener)
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	cc, err := grpc.DialContext(ctx, "localhost:2048", grpc.WithInsecure())
	require.NoError(t, err)
	defer cc.Close()

	client := pbgossip.NewGossipClient(cc)

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	stream, err := client.GossipStream(ctx)
	require.NoError(t, err)

	p, ok := peer.FromContext(stream.Context())
	require.True(t, ok)
	t.Log(p.Addr.String())
}
