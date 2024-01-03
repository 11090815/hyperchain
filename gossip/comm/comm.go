package comm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/gossip/api"
	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/gossip/discovery"
	"github.com/11090815/hyperchain/gossip/identity"
	"github.com/11090815/hyperchain/gossip/metrics"
	"github.com/11090815/hyperchain/gossip/protoext"
	"github.com/11090815/hyperchain/gossip/util"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
	"github.com/11090815/hyperchain/vars"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type Comm interface {
	GetPKIid() common.PKIid

	Send(msg *protoext.SignedGossipMessage, peers ...*discovery.NetworkMember)

	SendWithAck(msg *protoext.SignedGossipMessage, timeout time.Duration, minAck int, peers ...*discovery.NetworkMember) SendResults

	// Probe 探测远程节点，如果有响应则返回 nil，如果没有响应则返回错误信息。
	Probe(peer *discovery.NetworkMember) error

	Handshake(peer *discovery.NetworkMember) (api.PeerIdentity, error)

	Accept(common.MessageAcceptor) <-chan protoext.ReceivedMessage

	PresumedDead() <-chan common.PKIid

	IdentitySwitch() <-chan common.PKIid

	CloseConn(peer *discovery.NetworkMember)

	SetLogger(logger *hlogging.HyperchainLogger)

	Stop()
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

const (
	handshakeTimeout    = 10 * time.Second
	DefaultDialTimeout  = 3 * time.Second
	DefaultConnTimeout  = 2 * time.Second
	DefaultRecvBuffSize = 20
	DefaultSendBuffSize = 20
)

var errProbe = errors.New("probe")

type CommConfig struct {
	DialTimeout  time.Duration // 建立连接的超时时间，默认 3 秒
	ConnTimeout  time.Duration // 发送/接收消息的超时时间，默认 2 秒
	RecvBuffSize int
	SendBuffSize int
}

type commImpl struct {
	pkiID              common.PKIid
	identity           api.PeerIdentity
	idMapper           identity.Mapper
	connStore          *connectionStore
	handshakeTimeout   time.Duration // 握手的超时时间，默认是 10 秒
	deadPeerCh         chan common.PKIid
	identityChanges    chan common.PKIid
	stopCh             chan struct{}
	stopWg             sync.WaitGroup
	logger             *hlogging.HyperchainLogger
	advisor            api.SecurityAdvisor
	tlsCerts           *common.TLSCertificates
	pubsub             *util.PubSub
	receivedMessageChs []chan protoext.ReceivedMessage
	metrics            *metrics.CommMetrics
	msgPublisher       *ChannelDeMultiplexer
	opts               []grpc.DialOption
	secureDialOpts     func() []grpc.DialOption
	config             CommConfig
	lock               *sync.Mutex
}

func NewCommInstance(s *grpc.Server, certs *common.TLSCertificates, idStore identity.Mapper, peerIdentity api.PeerIdentity, secureDialOpts api.PeerSecureDialOpts, sa api.SecurityAdvisor, commMetrics *metrics.CommMetrics, config CommConfig, dialOpts ...grpc.DialOption) (Comm, error) {
	inst := &commImpl{
		pkiID:              idStore.GetPKIidOfCert(peerIdentity),
		identity:           peerIdentity,
		idMapper:           idStore,
		handshakeTimeout:   10 * time.Second,
		deadPeerCh:         make(chan common.PKIid, 100),
		identityChanges:    make(chan common.PKIid, 1),
		stopCh:             make(chan struct{}),
		logger:             util.GetLogger(util.CommLogger, ""),
		advisor:            sa,
		tlsCerts:           certs,
		pubsub:             util.NewPubSub(),
		receivedMessageChs: make([]chan protoext.ReceivedMessage, 0),
		metrics:            commMetrics,
		msgPublisher:       NewChannelDeMultiplexer(),
		opts:               dialOpts,
		secureDialOpts:     secureDialOpts,
		config:             config,
		lock:               &sync.Mutex{},
	}

	connConfig := ConnConfig{
		RecvBuffSize: config.RecvBuffSize,
		SendBuffSize: config.SendBuffSize,
	}

	inst.connStore = newConnectionStore(inst, inst.logger, connConfig)
	pbgossip.RegisterGossipServer(s, inst)

	return inst, nil
}

// Ping 和 GossipStream 实现 GossipServer 接口。
func (impl *commImpl) Ping(context.Context, *pbgossip.Empty) (*pbgossip.Empty, error) {
	return &pbgossip.Empty{}, nil
}

// GossipStream 实现 GossipServer 接口。
//
// TODO GossipStream 是什么时候调用的？
func (impl *commImpl) GossipStream(stream pbgossip.Gossip_GossipStreamServer) error {
	if impl.isStopped() {
		return vars.NewPathError("communicate module is closed")
	}

	impl.logger.Debugf("Peer %s call GossipStream.", impl.pkiID.String())
	// 我并非发起者，我的 tls 证书是 server 证书，不是 client 证书。
	connInfo, err := impl.authenticateRemotePeer(stream, false, false)
	if err == errProbe {
		impl.logger.Infof("The remote peer %s@%s probed us.", connInfo.PKIid.String(), connInfo.Endpoint)
		return nil
	}

	if err != nil {
		impl.logger.Errorf("Gossip stream failed, because %s.", err.Error())
		return vars.NewPathError(err.Error())
	}
	impl.logger.Debugf("Servicing %s.", extractRemoteAddress(stream))

	conn := impl.connStore.onConnected(stream, connInfo, impl.metrics)

	// 把收到的消息包装一下，添加对方的 ConnectionInfo 和 connection 网络连接。
	h := func(signedMsg *protoext.SignedGossipMessage) {
		impl.msgPublisher.DeMultiplex(&ReceivedMessageImpl{
			conn:                conn,
			signedGossipMessage: signedMsg,
			connInfo:            connInfo,
		})
	}

	conn.handler = interceptAcks(h, connInfo.PKIid, impl.pubsub)

	defer func() {
		impl.connStore.closeConnByPKIid(connInfo.PKIid)
	}()

	return conn.serviceConnection()
}

func (impl *commImpl) GetPKIid() common.PKIid {
	return impl.pkiID
}

// Send 以非阻塞的方式向给定的若干个节点发送消息。
func (impl *commImpl) Send(msg *protoext.SignedGossipMessage, peers ...*discovery.NetworkMember) {
	if impl.isStopped() || len(peers) == 0 {
		return
	}
	for _, peer := range peers {
		go func(peer *discovery.NetworkMember, msg *protoext.SignedGossipMessage) {
			impl.sendToEndpoint(peer, msg, false)
		}(peer, msg)
	}
}

// SendWithAck 给若干个节点发送消息，并且至少有 minAck 个节点给了回复才算发送成功。
func (impl *commImpl) SendWithAck(msg *protoext.SignedGossipMessage, timeout time.Duration, minAck int, peers ...*discovery.NetworkMember) SendResults {
	var err error
	var results SendResults

	if impl.isStopped() {
		err = errors.New("communicate module is stopped")
		for _, peer := range peers {
			results = append(results, SendResult{
				error:         err,
				NetworkMember: *peer,
			})
		}
		return results
	}

	sendFunc := func(peer *discovery.NetworkMember, msg *protoext.SignedGossipMessage) {
		impl.sendToEndpoint(peer, msg, true)
	}

	subscriptions := make(map[string]func() error)
	for _, peer := range peers {
		topic := topicForAck(msg.GossipMessage.Nonce, peer.PKIid)
		sub := impl.pubsub.Subscribe(topic, timeout)
		subscriptions[peer.PKIid.String()] = func() error {
			msg, err := sub.Listen()
			if err != nil {
				return vars.NewPathError(err.Error())
			}
			if msg, isAck := msg.(*pbgossip.Acknowledgement); !isAck {
				return vars.NewPathError(fmt.Sprintf("excepted *pbgossip.Acknowledgement, but got %T", msg))
			} else {
				if msg.Error != "" {
					return vars.NewPathError(msg.Error)
				}
			}
			return nil
		}
	}
	waitForAck := func(peer *discovery.NetworkMember) error {
		return subscriptions[peer.PKIid.String()]()
	}
	ackOperation := &ackSendOpration{
		snd:        sendFunc,
		waitForAck: waitForAck,
	}
	return ackOperation.send(msg, minAck, peers...)
}

// Probe 向对方发送一个 ping 消息。
func (impl *commImpl) Probe(peer *discovery.NetworkMember) error {
	if impl.isStopped() {
		return vars.NewPathError("communicate module is stopped")
	}
	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, impl.secureDialOpts()...)
	dialOpts = append(dialOpts, grpc.WithBlock())
	dialOpts = append(dialOpts, impl.opts...)
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, impl.config.DialTimeout)
	defer cancel()
	cc, err := grpc.DialContext(ctx, peer.ExternalEndpoint, dialOpts...)
	if err != nil {
		return vars.NewPathError(err.Error())
	}
	defer cc.Close()
	client := pbgossip.NewGossipClient(cc)
	ctx, cancel = context.WithTimeout(context.Background(), impl.config.ConnTimeout)
	defer cancel()
	_, err = client.Ping(ctx, &pbgossip.Empty{})
	return err
}

func (impl *commImpl) Handshake(peer *discovery.NetworkMember) (api.PeerIdentity, error) {
	impl.logger.Debugf("Handshake with %s@%s.", peer.PKIid.String(), peer.ExternalEndpoint)
	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, impl.secureDialOpts()...)
	dialOpts = append(dialOpts, grpc.WithBlock())
	dialOpts = append(dialOpts, impl.opts...)

	// 1. 实例化一个 grpc 连接
	ctx, cancel := context.WithTimeout(context.Background(), impl.config.DialTimeout)
	defer cancel()
	cc, err := grpc.DialContext(ctx, peer.ExternalEndpoint, dialOpts...)
	if err != nil {
		return nil, vars.NewPathError(err.Error())
	}
	defer cc.Close()

	// 2. 根据 grpc 连接实例化一个客户端
	client := pbgossip.NewGossipClient(cc)

	// 3. 利用客户端 ping 一下对方
	ctx, cancel = context.WithTimeout(context.Background(), impl.config.ConnTimeout)
	defer cancel()
	if _, err = client.Ping(ctx, &pbgossip.Empty{}); err != nil {
		return nil, vars.NewPathError(err.Error())
	}

	// 4. 验证对方的身份
	ctx, cancel = context.WithTimeout(context.Background(), impl.handshakeTimeout)
	defer cancel()
	stream, err := client.GossipStream(ctx)
	if err != nil {
		return nil, vars.NewPathError(err.Error())
	}
	connInfo, err := impl.authenticateRemotePeer(stream, true, true)
	if err != nil {
		impl.logger.Errorf("Failed hand shaking, because %s.", err.Error())
		return nil, vars.NewPathError(err.Error())
	}
	if len(peer.PKIid) != 0 && !bytes.Equal(peer.PKIid, connInfo.PKIid) {
		return nil, vars.NewPathError(fmt.Sprintf("remote peer provided a different pki-id %s from expected pki-id %s", peer.PKIid.String(), connInfo.PKIid.String()))
	}
	return connInfo.Identity, nil
}

func (impl *commImpl) Accept(acceptor common.MessageAcceptor) <-chan protoext.ReceivedMessage {
	genericCh := impl.msgPublisher.AddChannel(acceptor)
	specifiedCh := make(chan protoext.ReceivedMessage, 10)

	if impl.isStopped() {
		impl.logger.Warn("Communicate module is stopped, returing empty message channel.")
		return specifiedCh
	}

	impl.lock.Lock()
	impl.receivedMessageChs = append(impl.receivedMessageChs, specifiedCh)
	impl.lock.Unlock()

	impl.stopWg.Add(1)
	go func() {
		defer impl.stopWg.Done()
		for {
			select {
			case msg, chanOpen := <-genericCh:
				if !chanOpen {
					return
				}
				select {
				case specifiedCh <- msg.(*ReceivedMessageImpl):
				case <-impl.stopCh:
					return
				}
			case <-impl.stopCh:
				return
			}
		}
	}()

	return specifiedCh
}

func (impl *commImpl) PresumedDead() <-chan common.PKIid {
	return impl.deadPeerCh
}

func (impl *commImpl) IdentitySwitch() <-chan common.PKIid {
	return impl.identityChanges
}

func (impl *commImpl) CloseConn(peer *discovery.NetworkMember) {
	impl.logger.Debugf("Closing connection for %s.", peer.String())
	impl.connStore.closeConnByPKIid(peer.PKIid)
}

func (impl *commImpl) SetLogger(logger *hlogging.HyperchainLogger) {
	impl.logger = logger
}

func (impl *commImpl) Stop() {
	if impl.isStopped() {
		return
	}

	impl.logger.Info("Stopping communicate module.")
	impl.connStore.shutdown()
	impl.msgPublisher.Stop()
	close(impl.stopCh)
	impl.stopWg.Wait()
	impl.closeSubscriptions()
}

func (impl *commImpl) closeSubscriptions() {
	impl.lock.Lock()
	defer impl.lock.Unlock()
	for _, ch := range impl.receivedMessageChs {
		close(ch)
	}
}

func (impl *commImpl) sendToEndpoint(peer *discovery.NetworkMember, msg *protoext.SignedGossipMessage, shouldBlock bool) {
	if impl.isStopped() {
		return
	}

	conn, err := impl.connStore.getConnection(peer)
	if err == nil {
		disConnectOnErr := func(err error) {
			impl.logger.Warnf("%s@%s isn't responsive, because %s.", peer.PKIid.String(), peer.ExternalEndpoint, err.Error())
			impl.disconnect(peer.PKIid) // 消息一旦发送失败，就断开与其之间的连接
			conn.close()
		}
		impl.logger.Debugf("Sending message %s to peer %s@%s.", msg.String(), peer.PKIid.String(), peer.ExternalEndpoint)
		conn.send(msg, disConnectOnErr, shouldBlock)
		return
	}
	impl.logger.Warnf("Failed obtaining connection for %s, because %s.", peer.String(), err.Error())
	impl.disconnect(peer.PKIid)
}

func (impl *commImpl) createConnectionMsg(pkiID common.PKIid, certHash []byte, cert api.PeerIdentity, signer protoext.SignerFunc, isProbe bool) (*protoext.SignedGossipMessage, error) {
	m := &pbgossip.GossipMessage{
		Tag:   pbgossip.GossipMessage_EMPTY,
		Nonce: 0,
		Content: &pbgossip.GossipMessage_Conn{
			Conn: &pbgossip.ConnEstablish{
				TlsCertHash: certHash,
				PkiId:       pkiID,
				Identity:    cert,
				Probe:       isProbe,
			},
		},
	}

	signedMsg := &protoext.SignedGossipMessage{
		GossipMessage: m,
	}

	_, err := signedMsg.Sign(signer)
	if err != nil {
		return nil, vars.NewPathError(fmt.Sprintf("failed creating connection message, because %s", err.Error()))
	}
	return signedMsg, nil
}

func (impl *commImpl) authenticateRemotePeer(s stream, initiator, isProbe bool) (*protoext.ConnectionInfo, error) {
	ctx := s.Context()
	remoteAddress := extractRemoteAddress(s)                 // 获取对方的网络地址
	remoteCertHash := extractCertificateHashFromContext(ctx) // 获取对方的 tls 身份证书哈希值
	impl.logger.Debugf("Start authenticating peer %s.", remoteAddress)
	var err error
	var connMsg *protoext.SignedGossipMessage
	useTLS := impl.tlsCerts != nil // 如果我们存储了 tls 证书，就说明我们采用了 tls 连接
	var selfCertHash []byte        // 自身的身份证书哈希值

	if useTLS {
		certReference := impl.tlsCerts.TLSServerCert
		if initiator { // 如果是发起者，则我的 tls 身份证书是客户端证书，TODO 谁是发起者？
			certReference = impl.tlsCerts.TLSClientCert
		}
		selfCertHash = certHashFromRawCert(certReference.Load().(*tls.Certificate).Certificate[0])
	}

	if useTLS && len(remoteCertHash) == 0 {
		impl.logger.Errorf("Remote peer %s didn't provide tls certificate.", remoteAddress)
		return nil, vars.NewPathError(fmt.Sprintf("failed authenticating remote peer %s, because missing tls certificate", remoteAddress))
	}

	// 给对方发送我的信息
	connMsg, err = impl.createConnectionMsg(impl.pkiID, selfCertHash, impl.identity, impl.idMapper.Sign, isProbe)
	if err != nil {
		return nil, vars.NewPathError(fmt.Sprintf("failed authenticate remote peer, because %s", err.Error()))
	}
	impl.logger.Debugf("Sending connection message %s to %s.", connMsg.String(), remoteAddress)
	s.Send(connMsg.Envelope)

	// 等待对方回复我
	repliedMsg, err := readWithTimeout(s, impl.config.ConnTimeout, remoteAddress)
	if err != nil {
		impl.logger.Errorf("Failed waiting for replied message, because %s.", err.Error())
		return nil, vars.NewPathError(fmt.Sprintf("failed authenticating remote peer %s, because %s", remoteAddress, err.Error()))
	}

	// 初步检查对方回复的消息是否正确
	repliedConnMsg := repliedMsg.GossipMessage.GetConn()
	if repliedConnMsg == nil {
		impl.logger.Errorf("Expected connection establish message from %s, but got %s.", remoteAddress, repliedMsg.String())
		return nil, vars.NewPathError(fmt.Sprintf("failed authenticating remote peer, expected connection establish message from %s, but got %s", remoteAddress, repliedMsg.String()))
	}

	if len(repliedConnMsg.PkiId) == 0 {
		impl.logger.Errorf("Remote peer %s didn't provide pki-id.", remoteAddress)
		return nil, vars.NewPathError(fmt.Sprintf("failed authenticating remote peer, remote peer %s didn't provide pki-id", remoteAddress))
	}

	// 将对方的 tls 身份证书存储在本地
	impl.logger.Debugf("Received %s from %s.", repliedMsg.String(), remoteAddress)
	if err = impl.idMapper.Put(repliedConnMsg.PkiId, repliedConnMsg.Identity); err != nil {
		impl.logger.Errorf("Can't store identity for %s, because %s.", common.PKIidToStr(repliedConnMsg.PkiId), err.Error())
		return nil, vars.NewPathError(fmt.Sprintf("failed authenticating remote peer %s, because can't store identity for him, the error is %s", remoteAddress, err.Error()))
	}

	// 获得了对方的信息
	connInfo := &protoext.ConnectionInfo{
		PKIid:    repliedConnMsg.PkiId,
		Identity: repliedConnMsg.Identity,
		Endpoint: remoteAddress,
		Auth: &protoext.AuthInfo{
			SignedData: repliedMsg.Envelope.Payload,
			Signature:  repliedMsg.Envelope.Signature,
		},
	}

	// 进一步验证对方的信息
	if useTLS {
		if !bytes.Equal(remoteCertHash, repliedConnMsg.TlsCertHash) {
			impl.logger.Errorf("Failed authenticating remote peer %s, expected %s in the hash of remote tls certificate, but got %s.", remoteAddress, hex.EncodeToString(remoteCertHash), hex.EncodeToString(repliedConnMsg.TlsCertHash))
			return nil, vars.NewPathError(fmt.Sprintf("failed authenticating remote peer %s, expected %s in the hash of remote tls certificate, but got %s", remoteAddress, hex.EncodeToString(remoteCertHash), hex.EncodeToString(repliedConnMsg.TlsCertHash)))
		}
	}

	verifier := func(peerIdentity api.PeerIdentity, signature, message []byte) error {
		pkiID := impl.idMapper.GetPKIidOfCert(peerIdentity)
		return impl.idMapper.Verify(pkiID, signature, message)
	}
	err = repliedMsg.Verify(repliedConnMsg.Identity, verifier)
	if err != nil {
		impl.logger.Errorf("Failed verifying signature from %s, the error is %s.", remoteAddress, err.Error())
		return nil, vars.NewPathError(fmt.Sprintf("failed authenticating remote peer %s, becuase the signature is invalid", remoteAddress))
	}

	impl.logger.Debugf("Successfully authenticated %s.", remoteAddress)

	if repliedConnMsg.Probe {
		return connInfo, errProbe
	}

	return connInfo, nil
}

func (impl *commImpl) disconnect(pkiID common.PKIid) {
	select {
	case impl.deadPeerCh <- pkiID:
	case <-impl.stopCh:
		return
	}
	impl.connStore.closeConnByPKIid(pkiID)
}

func (impl *commImpl) isStopped() bool {
	select {
	case <-impl.stopCh:
		return true
	default:
		return false
	}
}

func (impl *commImpl) createConnection(endpoint string, expectedPKIID common.PKIid) (*connection, error) {
	var err error
	var cc *grpc.ClientConn
	var stream pbgossip.Gossip_GossipStreamClient
	var pkiID common.PKIid
	var connInfo *protoext.ConnectionInfo
	var dialOpts []grpc.DialOption

	if impl.isStopped() {
		return nil, vars.NewPathError("communicate module is stopped")
	}

	// 1. 构造 grpc 拨号选项
	dialOpts = append(dialOpts, impl.secureDialOpts()...)
	dialOpts = append(dialOpts, grpc.WithBlock())
	dialOpts = append(dialOpts, impl.opts...)
	ctx, cancel := context.WithTimeout(context.Background(), impl.config.DialTimeout)
	defer cancel()

	// 2. 建立 grpc 连接
	cc, err = grpc.DialContext(ctx, endpoint, dialOpts...)
	if err != nil {
		return nil, vars.NewPathError(fmt.Sprintf("failed creating connection, because %s.", err.Error()))
	}

	// 3. 构建 gossip 客户端，并测试连通性
	client := pbgossip.NewGossipClient(cc)
	ctx, cancel = context.WithTimeout(context.Background(), impl.config.ConnTimeout)
	defer cancel()
	if _, err = client.Ping(ctx, &pbgossip.Empty{}); err != nil {
		cc.Close()
		return nil, vars.NewPathError(fmt.Sprintf("network connectivity test failed, because %s.", err.Error()))
	}

	// 4. 根据 gossip 客户端创建消息流，借助消息流验证对方身份的合法性
	ctx, cancel = context.WithCancel(context.Background())
	if stream, err = client.GossipStream(ctx); err == nil {
		// 因为我在给 endpoint 发送消息时，发现还没与其建立连接，所以主动与其建立连接，因此我们是作为客户端，对方是服务端
		// （rpc 服务中，被连接的是服务端，主动发起连接的是客户端）。
		// 现在开始，双方开始互相验证对方身份的合法性。
		connInfo, err = impl.authenticateRemotePeer(stream, true, false)
		if err == nil {
			pkiID = connInfo.PKIid
			if len(expectedPKIID) != 0 && !bytes.Equal(pkiID, expectedPKIID) {
				actualOrg := impl.advisor.OrgByPeerIdentity(connInfo.Identity)
				storedIdentity, _ := impl.idMapper.Get(expectedPKIID)
				oldOrg := impl.advisor.OrgByPeerIdentity(storedIdentity)
				if !bytes.Equal(actualOrg, oldOrg) {
					impl.logger.Errorf("Remote endpoint claims to be a different peer, expected %s, but got %s.", expectedPKIID.String(), pkiID.String())
					cc.Close()
					cancel()
					return nil, vars.NewPathError(fmt.Sprintf("failed creating connection, because remote endpoint claims to be a different peer, expected %s, but got %s", expectedPKIID.String(), pkiID.String()))
				} else {
					impl.logger.Infof("Peer %s changed his pki-id from %s to %s.", endpoint, expectedPKIID.String(), pkiID.String())
					impl.identityChanges <- expectedPKIID
				}
			}

			connConfig := ConnConfig{
				RecvBuffSize: impl.config.RecvBuffSize,
				SendBuffSize: impl.config.SendBuffSize,
			}
			conn := newConnection(client, cc, stream, impl.metrics, connConfig)
			conn.info = connInfo
			conn.logger = util.GetLogger(util.ConnLogger, endpoint)
			conn.cancel = cancel

			// 如果发送来的不是 ack 消息，则采用此 handler 处理消息
			var h handler = func(m *protoext.SignedGossipMessage) {
				impl.msgPublisher.DeMultiplex(&ReceivedMessageImpl{
					conn:                conn,
					signedGossipMessage: m,
					connInfo:            connInfo,
				})
			}
			conn.handler = interceptAcks(h, connInfo.PKIid, impl.pubsub)
			return conn, nil
		}
	}
	cc.Close()
	cancel()
	return nil, vars.NewPathError(err.Error())
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

func extractRemoteAddress(s stream) string {
	var remoteAddress string
	p, ok := peer.FromContext(s.Context()) // 在生成 stream 时，会自动注册
	if ok {
		if address := p.Addr; address != nil {
			remoteAddress = address.String()
		}
	}
	return remoteAddress
}

func extractCertificateHashFromContext(ctx context.Context) []byte {
	p, exists := peer.FromContext(ctx)
	if !exists {
		return nil
	}

	authInfo := p.AuthInfo
	if authInfo == nil {
		return nil
	}

	tlsInfo, ok := authInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}

	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	raw := certs[0].Raw
	return certHashFromRawCert(raw)
}

func certHashFromRawCert(raw []byte) []byte {
	if len(raw) == 0 {
		return nil
	}

	csp, _ := bccsp.NewBCCSP(nil)
	h, _ := csp.GetHash(&bccsp.SHA256Opts{})
	h.Write(raw)
	return h.Sum(nil)
}

func readWithTimeout(s stream, timeout time.Duration, address string) (*protoext.SignedGossipMessage, error) {
	inCh := make(chan *protoext.SignedGossipMessage, 1)
	errCh := make(chan error, 1)

	go func() {
		if m, err := s.Recv(); err == nil {
			signedMsg, err := protoext.EnvelopeToSignedGossipMessage(m)
			if err != nil {
				errCh <- vars.NewPathError(err.Error())
				return
			}
			inCh <- signedMsg
		}
	}()

	select {
	case <-time.After(timeout):
		return nil, vars.NewPathError(fmt.Sprintf("timed out waiting for connection message from %s", address))
	case m := <-inCh:
		return m, nil
	case err := <-errCh:
		return nil, err
	}
}
