package comm

import (
	"context"
	"fmt"
	"sync"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/gossip/discovery"
	"github.com/11090815/hyperchain/gossip/metrics"
	"github.com/11090815/hyperchain/gossip/protoext"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
	"github.com/11090815/hyperchain/vars"
	"google.golang.org/grpc"
)

type handler func(message *protoext.SignedGossipMessage)

const (
	blockingSend    = true
	nonBlockingSend = false
)

type connectionStore struct {
	config          ConnConfig
	comm            *commImpl
	pki2Connections map[string]*connection
	// destinationLocks map[string]*sync.Mutex // pki-id => lock
	logger    *hlogging.HyperchainLogger
	isClosing bool
	mutex     *sync.RWMutex
}

func newConnectionStore(comm *commImpl, logger *hlogging.HyperchainLogger, config ConnConfig) *connectionStore {
	return &connectionStore{
		config:          config,
		comm:            comm,
		pki2Connections: make(map[string]*connection),
		logger: logger,
		mutex:  &sync.RWMutex{},
	}
}

// getConnection 根据给定的 peer 节点的 pki-id，从连接池里获取对应的网络连接，如果不存在，则建立与其之间
// 的连接。
func (cs *connectionStore) getConnection(peer *discovery.NetworkMember) (*connection, error) {
	cs.mutex.RLock()
	isClosing := cs.isClosing
	cs.mutex.RUnlock()

	if isClosing {
		return nil, vars.NewPathError("connection store is closed")
	}

	cs.mutex.RLock()
	conn, exists := cs.pki2Connections[peer.PKIid.String()]
	if exists {
		cs.mutex.RUnlock()
		return conn, nil
	}
	cs.mutex.RUnlock()

	cs.logger.Debugf("The connection to \"%s@%s\" has not yet been established, start creating connection now.", peer.PKIid, peer.ExternalEndpoint)
	createConnection, err := cs.comm.createConnection(peer.ExternalEndpoint, peer.PKIid)

	cs.mutex.RLock()
	isClosing = cs.isClosing
	cs.mutex.RUnlock()

	if isClosing {
		return nil, vars.NewPathError("connection store is closed after creating new connection")
	}

	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	// 再次检查一下，因为对方在我们尝试连接它时，它也在主动与我们建立连接
	conn, exists = cs.pki2Connections[peer.PKIid.String()]
	if exists {
		if createConnection != nil {
			createConnection.close()
		}
		return conn, nil
	}

	if err != nil {
		return nil, vars.NewPathError(fmt.Sprintf("failed creating new connection, because %s", err.Error()))
	}

	// 新连接的 id 与旧连接的 id 冲突，关闭旧连接。
	if conn, exists = cs.pki2Connections[createConnection.info.PKIid.String()]; exists {
		conn.close()
	}

	conn = createConnection
	cs.pki2Connections[createConnection.info.PKIid.String()] = conn

	go conn.serviceConnection()

	return conn, nil
}

func (cs *connectionStore) onConnected(serverStream pbgossip.Gossip_GossipStreamServer, connInfo *protoext.ConnectionInfo, metrics *metrics.CommMetrics) *connection {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	if c, exists := cs.pki2Connections[connInfo.PKIid.String()]; exists {
		c.close()
	}

	conn := newConnection(nil, nil, serverStream, metrics, cs.config)
	conn.info = connInfo
	conn.logger = cs.logger
	cs.pki2Connections[connInfo.PKIid.String()] = conn
	return conn
}

func (cs *connectionStore) connNum() int {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	return len(cs.pki2Connections)
}

func (cs *connectionStore) closeConnByPKIid(pkiID common.PKIid) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	if conn, exists := cs.pki2Connections[pkiID.String()]; exists {
		conn.close()
		delete(cs.pki2Connections, pkiID.String())
	}
}

func (cs *connectionStore) shutdown() {
	cs.mutex.RLock()
	isClosing := cs.isClosing
	cs.mutex.RUnlock()

	if isClosing {
		return
	}

	cs.mutex.Lock()
	cs.isClosing = true
	for _, conn := range cs.pki2Connections {
		conn.close()
	}
	cs.pki2Connections = make(map[string]*connection)
	cs.mutex.Unlock()
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type connection struct {
	info         *protoext.ConnectionInfo
	outBuf       chan *msgSending
	logger       *hlogging.HyperchainLogger
	handler      handler
	conn         *grpc.ClientConn
	client       pbgossip.GossipClient
	gossipStream stream
	recvBuffSize int
	metrics      *metrics.CommMetrics
	cancel       context.CancelFunc
	stopCh       chan struct{}
}

func newConnection(client pbgossip.GossipClient, conn *grpc.ClientConn, s stream, metrics *metrics.CommMetrics, config ConnConfig) *connection {
	c := &connection{
		metrics:      metrics,
		outBuf:       make(chan *msgSending, config.SendBuffSize),
		client:       client,
		conn:         conn,
		gossipStream: s,
		stopCh:       make(chan struct{}),
		recvBuffSize: config.RecvBuffSize,
	}
	return c
}

type ConnConfig struct {
	RecvBuffSize int
	SendBuffSize int
}

type msgSending struct {
	envelope *pbgossip.Envelope
	onErr    func(error)
}

type stream interface {
	Send(envelope *pbgossip.Envelope) error
	Recv() (*pbgossip.Envelope, error)
	Context() context.Context
}

// send 传入的第三个参数 shouldBlock 决定了如果发送通道已经满了，该如何对待要发送出去的消息的态度。如果 shouldBlock 等于 true，
// 则表明如果发送通道满了，则会不停地尝试往通道里传送待发送消息，直到消息被顺利送入通道内。否则就将待发送消息放弃掉。
func (c *connection) send(msg *protoext.SignedGossipMessage, onErr func(error), shouldBlock bool) {
	m := &msgSending{
		envelope: msg.Envelope,
		onErr:    onErr,
	}

	select {
	case c.outBuf <- m:
		// 放到发送通道里
	case <-c.stopCh:
		c.logger.Debugf("Aborting sending to %s@%s, because connection is closing.", c.info.PKIid.String(), c.info.Endpoint)
	default:
		if shouldBlock {
			select {
			case c.outBuf <- m:
			case <-c.stopCh:
			}
		} else {
			c.metrics.BufferOverflow.Add(1)
			c.logger.Warnf("Buffer to %s@%s overflowed, dropping message %s.", c.info.PKIid.String(), c.info.Endpoint, msg)
		}
	}
}

func (c *connection) writeToStream() {
	stream := c.gossipStream
	for {
		select {
		case m := <-c.outBuf:
			err := stream.Send(m.envelope)
			if err != nil {
				go m.onErr(err)
				return
			}
		case <-c.stopCh:
			return
		}
	}
}

func (c *connection) readFromStream(errCh chan error, msgCh chan *protoext.SignedGossipMessage) {
	stream := c.gossipStream

	for {
		select {
		case <-c.stopCh:
			return
		default:
			envelope, err := stream.Recv()
			if err != nil {
				errCh <- err
				c.logger.Errorf("Got error when reading from stream, error is \"%s\".", err.Error())
				return
			}
			c.metrics.ReceivedMessages.Add(1)
			signedMsg, err := protoext.EnvelopeToSignedGossipMessage(envelope)
			if err != nil {
				errCh <- err
				c.logger.Errorf("Got an invalid envelope from stream, error is \"%s\".", err.Error())
				return
			}
			select {
			case <-c.stopCh:
			case msgCh <- signedMsg:
			}
		}
	}
}

func (c *connection) serviceConnection() error {
	errCh := make(chan error, 1)
	msgCh := make(chan *protoext.SignedGossipMessage, c.recvBuffSize)

	go c.readFromStream(errCh, msgCh)
	go c.writeToStream()

	for {
		select {
		case <-c.stopCh:
			return nil
		case err := <-errCh:
			return err
		case msg := <-msgCh:
			c.handler(msg)
		}
	}
}

func (c *connection) close() {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
		if c.cancel != nil {
			c.cancel()
		}
		if c.conn != nil {
			c.conn.Close()
		}
		c.logger.Debugf("Close connection to %s@%s.", c.info.PKIid.String(), c.info.Endpoint)
	}
}
