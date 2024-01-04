package comm

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/common/metrics/disabled"
	"github.com/11090815/hyperchain/gossip/api"
	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/gossip/discovery"
	"github.com/11090815/hyperchain/gossip/identity"
	"github.com/11090815/hyperchain/gossip/metrics"
	"github.com/11090815/hyperchain/gossip/protoext"
	"github.com/11090815/hyperchain/gossip/util"
	"github.com/11090815/hyperchain/internal/pkg/comm"
	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func TestMutualParallelSendWithAck(t *testing.T) {
	msgNum := 20

	comm1, port1 := newCommInstance(t, mockSecurity)
	comm2, port2 := newCommInstance(t, mockSecurity)
	defer comm1.Stop()
	defer comm2.Stop()

	acceptData := func(o interface{}) bool {
		m := o.(protoext.ReceivedMessage).GetSignedGossipMessage().GossipMessage
		return m.GetDataMsg() != nil
	}

	inc1 := comm1.Accept(acceptData)
	inc2 := comm2.Accept(acceptData)

	comm1.Send(createSigendGossipMsg(), remotePeer(port2))
	<-inc2

	for i := 0; i < msgNum; i++ {
		go comm1.SendWithAck(createSigendGossipMsg(), time.Second*5, 1, remotePeer(port2))
	}

	for i := 0; i < msgNum; i++ {
		go comm2.SendWithAck(createSigendGossipMsg(), time.Second*5, 1, remotePeer(port1))
	}

	go func() {
		for i := 0; i < msgNum; i++ {
			<-inc1
		}
	}()

	for i := 0; i < msgNum; i++ {
		<-inc2
	}
}

func TestNewConnComing(t *testing.T) {
	comm1, _ := newCommInstance(t, mockSecurity)
	comm2, port2 := newCommInstance(t, mockSecurity)

	comm1.SetLogger(util.GetLogger(util.CommLogger, "comm1"))
	comm2.SetLogger(util.GetLogger(util.CommLogger, "comm2"))

	acceptData := func(o interface{}) bool {
		m := o.(protoext.ReceivedMessage).GetSignedGossipMessage().GossipMessage
		return m.GetDataMsg() != nil
	}

	inc2 := comm2.Accept(acceptData)
	comm1.Send(createSigendGossipMsg(), remotePeer(port2))
	<-inc2

	comm1.Stop()
	comm2.Stop()
}

func TestHandshake(t *testing.T) {
	signer := func(msg []byte) ([]byte, error) {
		mac := hmac.New(sha256.New, hmackey)
		mac.Write(msg)
		return mac.Sum(nil), nil
	}

	mutator := func(msg *protoext.SignedGossipMessage) *protoext.SignedGossipMessage {
		return msg
	}

	assertPositivePath := func(msg protoext.ReceivedMessage, endpoint string) {
		expectedPKIid := common.PKIid(endpoint)
		expectedIdentity := api.PeerIdentity(endpoint)
		require.Equal(t, expectedPKIid, msg.GetConnectionInfo().PKIid)
		require.Equal(t, expectedIdentity, msg.GetConnectionInfo().Identity)
		require.NotNil(t, msg.GetConnectionInfo().Auth)
		sig, _ := mockSecurity.Sign(msg.GetConnectionInfo().Auth.SignedData)
		require.Equal(t, sig, msg.GetConnectionInfo().Auth.Signature)
	}

	// 1. 不设置 TLS
	port, endpoint, listener := getAvailablePort(t)
	s := grpc.NewServer()
	id := api.PeerIdentity(endpoint)
	idMapper := identity.NewIdentityMapper(mockSecurity, id, noopPurgeIdentity, mockSecurity)
	comm, err := NewCommInstance(s, nil, idMapper, id, func() []grpc.DialOption {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}, mockSecurity, disabledMetrics, testCommConfig)
	require.NoError(t, err)
	comm.SetLogger(util.GetLogger(util.CommLogger, "comm"))
	go s.Serve(listener)
	var msg protoext.ReceivedMessage
	_, tempEndpoint, tempListener := getAvailablePort(t)
	acceptCh := handshaker(t, port, tempEndpoint, comm, mutator, none)
	select {
	case <-time.After(time.Second * 4):
		require.FailNow(t, "Didn't get the message in time")
	case msg = <-acceptCh:
	}
	require.Equal(t, common.PKIid(tempEndpoint), msg.GetConnectionInfo().PKIid)
	require.Equal(t, api.PeerIdentity(tempEndpoint), msg.GetConnectionInfo().Identity)
	sig, _ := mockSecurity.Sign(msg.GetConnectionInfo().Auth.SignedData)
	require.Equal(t, sig, msg.GetConnectionInfo().Auth.Signature)
	comm.Stop()
	s.Stop()
	listener.Close()
	tempListener.Close()
	time.Sleep(time.Second)

	comm2, port := newCommInstance(t, mockSecurity)
	comm2.SetLogger(util.GetLogger(util.CommLogger, "comm2"))
	defer comm2.Stop()
	_, tempEndpoint, tempListener = getAvailablePort(t)
	acceptCh = handshaker(t, port, tempEndpoint, comm2, mutator, mutualTLS)
	select {
	case <-time.After(time.Second * 3):
		require.FailNow(t, "Didn't get the message in time")
	case msg = <-acceptCh:
	}
	assertPositivePath(msg, tempEndpoint)
	tempListener.Close()

	_, tempEndpoint, tempListener = getAvailablePort(t)
	acceptCh = handshaker(t, port, tempEndpoint, comm2, mutator, onewayTLS)
	time.Sleep(time.Second)
	require.Equal(t, 0, len(acceptCh))
	tempListener.Close()

	_, tempEndpoint, tempListener = getAvailablePort(t)
	mutator = func(msg *protoext.SignedGossipMessage) *protoext.SignedGossipMessage {
		msg.Envelope.Signature = append(msg.Envelope.Signature, 0)
		return msg
	}
	acceptCh = handshaker(t, port, tempEndpoint, comm2, mutator, mutualTLS)
	time.Sleep(time.Second)
	require.Equal(t, 0, len(acceptCh))
	tempListener.Close()

	_, tempEndpoint, tempListener = getAvailablePort(t)
	mutator = func(msg *protoext.SignedGossipMessage) *protoext.SignedGossipMessage {
		msg.GossipMessage.GetConn().PkiId = []byte(tempEndpoint)
		msg.Sign(signer)
		return msg
	}
	_, tempEndpoint2, tempListener2 := getAvailablePort(t)
	acceptCh = handshaker(t, port, tempEndpoint2, comm2, mutator, mutualTLS)
	time.Sleep(time.Second)
	require.Equal(t, 0, len(acceptCh))
	tempListener.Close()
	tempListener2.Close()

	_, tempEndpoint, tempListener = getAvailablePort(t)
	mutator = func(msg *protoext.SignedGossipMessage) *protoext.SignedGossipMessage {
		msg.GossipMessage.GetConn().TlsCertHash = append(msg.GossipMessage.GetConn().TlsCertHash, 0)
		msg.Sign(signer)
		return msg
	}
	acceptCh = handshaker(t, port, tempEndpoint, comm2, mutator, mutualTLS)
	time.Sleep(time.Second)
	require.Equal(t, 0, len(acceptCh))
	tempListener.Close()

	_, tempEndpoint, tempListener = getAvailablePort(t)
	mutator = func(msg *protoext.SignedGossipMessage) *protoext.SignedGossipMessage {
		msg.GossipMessage.GetConn().PkiId = nil
		msg.Sign(signer)
		return msg
	}
	acceptCh = handshaker(t, port, tempEndpoint, comm2, mutator, mutualTLS)
	time.Sleep(time.Second)
	require.Equal(t, 0, len(acceptCh))
	tempListener.Close()

	_, tempEndpoint, tempListener = getAvailablePort(t)
	mutator = func(msg *protoext.SignedGossipMessage) *protoext.SignedGossipMessage {
		msg.GossipMessage.Content = &pbgossip.GossipMessage_Empty{
			Empty: &pbgossip.Empty{},
		}
		msg.Sign(signer)
		return msg
	}
	acceptCh = handshaker(t, port, tempEndpoint, comm2, mutator, mutualTLS)
	time.Sleep(time.Second)
	require.Equal(t, 0, len(acceptCh))
	tempListener.Close()

	_, tempEndpoint, tempListener = getAvailablePort(t)
	mutator = func(msg *protoext.SignedGossipMessage) *protoext.SignedGossipMessage {
		time.Sleep(time.Second * 5)
		return msg
	}
	acceptCh = handshaker(t, port, tempEndpoint, comm2, mutator, mutualTLS)
	time.Sleep(time.Second)
	require.Equal(t, 0, len(acceptCh))
	tempListener.Close()
}

func TestConnectUnexpectedPeer(t *testing.T) {
	identityByPort := func(port int) api.PeerIdentity {
		return api.PeerIdentity(fmt.Sprintf("127.0.0.1:%d", port))
	}

	comm1Port, gRPCServer1, certs1, secureDialOpts1, dialOpts1 := util.CreateGRPCLayer()
	comm2Port, gRPCServer2, certs2, secureDialOpts2, dialOpts2 := util.CreateGRPCLayer()
	comm3Port, gRPCServer3, certs3, secureDialOpts3, dialOpts3 := util.CreateGRPCLayer()
	comm4Port, gRPCServer4, certs4, secureDialOpts4, dialOpts4 := util.CreateGRPCLayer()

	customSecurity := &api.MockCryptoService{}

	customSecurity.On("OrgByPeerIdentity", identityByPort(comm1Port)).Return(api.OrgIdentity("O"))
	customSecurity.On("OrgByPeerIdentity", identityByPort(comm2Port)).Return(api.OrgIdentity("A"))
	customSecurity.On("OrgByPeerIdentity", identityByPort(comm3Port)).Return(api.OrgIdentity("B"))
	customSecurity.On("OrgByPeerIdentity", identityByPort(comm4Port)).Return(api.OrgIdentity("A"))

	comm1 := newCommInstanceWithoutMetrics(t, customSecurity, gRPCServer1, certs1, secureDialOpts1, dialOpts1...)
	comm2 := newCommInstanceWithoutMetrics(t, mockSecurity, gRPCServer2, certs2, secureDialOpts2, dialOpts2...)
	comm3 := newCommInstanceWithoutMetrics(t, mockSecurity, gRPCServer3, certs3, secureDialOpts3, dialOpts3...)
	comm4 := newCommInstanceWithoutMetrics(t, mockSecurity, gRPCServer4, certs4, secureDialOpts4, dialOpts4...)

	comm1.SetLogger(util.GetLogger(util.CommLogger, "comm1"))
	comm2.SetLogger(util.GetLogger(util.CommLogger, "comm2"))
	comm3.SetLogger(util.GetLogger(util.CommLogger, "comm3"))
	comm4.SetLogger(util.GetLogger(util.CommLogger, "comm4"))

	defer comm1.Stop()
	defer comm2.Stop()
	defer comm3.Stop()
	defer comm4.Stop()

	messagesForComm1 := comm1.Accept(acceptAll)
	messagesForComm2 := comm2.Accept(acceptAll)
	messagesForComm3 := comm3.Accept(acceptAll)

	comm4.Send(createSigendGossipMsg(), remotePeer(comm1Port))
	<-messagesForComm1
	comm1.CloseConn(remotePeer(comm4Port))

	unexpectedPeer := remotePeer(comm2Port)
	unexpectedPeer.PKIid = remotePeer(comm4Port).PKIid
	comm1.Send(createSigendGossipMsg(), unexpectedPeer)
	select {
	case <-messagesForComm2:
	case <-time.After(time.Second * 5):
		require.FailNow(t, "Didn't get the message in time")
	}

	unexpectedPeer = remotePeer(comm3Port)
	unexpectedPeer.PKIid = remotePeer(comm4Port).PKIid
	comm1.Send(createSigendGossipMsg(), unexpectedPeer)
	select {
	case <-messagesForComm3:
		require.FailNow(t, "Shouldn't get the message in time")
	case <-time.After(time.Second * 5):
	}
}

func TestGetConnectionInfo(t *testing.T) {
	comm1, port1 := newCommInstance(t, mockSecurity)
	comm2, _ := newCommInstance(t, mockSecurity)
	comm1.SetLogger(util.GetLogger(util.CommLogger, "comm1"))
	comm2.SetLogger(util.GetLogger(util.CommLogger, "comm2"))
	defer comm1.Stop()
	defer comm2.Stop()

	m1 := comm1.Accept(acceptAll)
	comm2.Send(createSigendGossipMsg(), remotePeer(port1))
	select {
	case <-time.After(time.Second * 3):
		require.FailNow(t, "Didn't get the message in time")
	case msg := <-m1:
		require.Equal(t, comm2.GetPKIid(), msg.GetConnectionInfo().PKIid)
		require.NotNil(t, msg.GetEnvelope())
	}
}

func TestCloseConn(t *testing.T) {
	comm1, port1 := newCommInstance(t, mockSecurity)
	comm1.SetLogger(util.GetLogger(util.CommLogger, "comm1"))
	defer comm1.Stop()
	acceptCh := comm1.Accept(acceptAll)

	cert := util.GenerateTLSCertificatesOrPanic()
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
	}
	transportCredential := credentials.NewTLS(tlsCfg)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	target := fmt.Sprintf("127.0.0.1:%d", port1)
	conn, err := grpc.DialContext(ctx, target, grpc.WithTransportCredentials(transportCredential), grpc.WithBlock())
	require.NoError(t, err)
	client := pbgossip.NewGossipClient(conn)
	stream, err := client.GossipStream(context.Background())
	require.NoError(t, err)
	time.Sleep(time.Second * 3)
	_, err = client.GossipStream(context.Background())
	require.NoError(t, err)
	time.Sleep(time.Second * 3)
	c := &commImpl{}
	tlsCertHash := certHashFromRawCert(tlsCfg.Certificates[0].Certificate[0])
	connMsg, _ := c.createConnectionMsg(common.PKIid("pki-id"), tlsCertHash, api.PeerIdentity("pki-id"), func(msg []byte) ([]byte, error) {
		mac := hmac.New(sha256.New, hmackey)
		mac.Write(msg)
		return mac.Sum(nil), nil
	}, false)
	require.Error(t, stream.Send(connMsg.Envelope))

	stream, err = client.GossipStream(context.Background())
	require.NoError(t, err)
	require.NoError(t, stream.Send(connMsg.Envelope))
	stream.Send(createSigendGossipMsg().Envelope)
	select {
	case <-time.After(time.Second * 2):
		require.FailNow(t, "Didn't get the message in time")
	case <-acceptCh:
	}

	comm1.CloseConn(&discovery.NetworkMember{PKIid: common.PKIid("pki-id")})
	time.Sleep(time.Second * 10)
	gotErr := false
	msg2send := createSigendGossipMsg()
	msg2send.GossipMessage.GetDataMsg().Payload = &pbgossip.Payload{
		Data: make([]byte, 1024*1024),
	}
	protoext.NoopSign(msg2send.GossipMessage)
	for i := 0; i < DefaultRecvBuffSize; i++ {
		err = stream.Send(msg2send.Envelope)
		if err != nil {
			t.Log(err)
			gotErr = true
			break
		}
	}
	require.True(t, gotErr)
}

func TestCommSend(t *testing.T) {
	sendMessages := func(c Comm, peer *discovery.NetworkMember, stopCh <-chan struct{}) {
		first := true
		ticker := time.NewTicker(time.Millisecond * 100)
		defer ticker.Stop()
		for {
			msg := createSigendGossipMsg()
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				c.Send(msg, peer)
				if first {
					time.Sleep(time.Second)
					first = false
				}
			}
		}
	}

	comm1, port1 := newCommInstance(t, mockSecurity)
	comm2, port2 := newCommInstance(t, mockSecurity)
	comm1.SetLogger(util.GetLogger(util.CommLogger, "comm1"))
	comm2.SetLogger(util.GetLogger(util.CommLogger, "comm2"))
	defer comm1.Stop()
	defer comm2.Stop()

	ch1 := comm1.Accept(acceptAll)
	ch2 := comm2.Accept(acceptAll)

	stopCh1 := make(chan struct{})
	stopCh2 := make(chan struct{})

	go sendMessages(comm1, remotePeer(port2), stopCh1)
	time.Sleep(time.Second * 3)
	go sendMessages(comm2, remotePeer(port1), stopCh2)

	c1recved := 0
	c2recved := 0

	totalMessagesRecved := (DefaultSendBuffSize + DefaultRecvBuffSize) * 2
	timer := time.NewTimer(time.Second * 300)

RECV:
	for {
		select {
		case <-ch1:
			c1recved++
			if c1recved == totalMessagesRecved {
				close(stopCh2)
			}
		case <-ch2:
			c2recved++
			if c2recved == totalMessagesRecved {
				close(stopCh1)
			}
		case <-timer.C:
			require.FailNow(t, "timed out waiting for messages to be received")
		default:
			if c1recved >= totalMessagesRecved && c2recved >= totalMessagesRecved {
				break RECV
			}
		}
	}

	t.Logf("c1 got %d messages\nc2 got %d messages", c1recved, c2recved)
}

func TestResponses(t *testing.T) {
	comm1, port1 := newCommInstance(t, mockSecurity)
	comm2, _ := newCommInstance(t, mockSecurity)
	comm1.SetLogger(util.GetLogger(util.CommLogger, "comm1"))
	comm2.SetLogger(util.GetLogger(util.CommLogger, "comm2"))

	defer comm1.Stop()
	defer comm2.Stop()

	wg := sync.WaitGroup{}

	msg := createSigendGossipMsg()
	wg.Add(1)
	go func() {
		inChan := comm1.Accept(acceptAll)
		wg.Done()
		for m := range inChan {
			reply := createSigendGossipMsg()
			reply.GossipMessage.Nonce = m.GetSignedGossipMessage().GossipMessage.GetNonce() + 1
			m.Respond(reply.GossipMessage)
		}
	}()
	expectedNOnce := msg.GossipMessage.Nonce + 1
	responsesFromComm1 := comm2.Accept(acceptAll)

	ticker := time.NewTicker(10 * time.Second)
	wg.Wait()
	comm2.Send(msg, remotePeer(port1))

	select {
	case <-ticker.C:
		require.Fail(t, "Haven't got response from comm1 within a timely manner")
		break
	case resp := <-responsesFromComm1:
		ticker.Stop()
		require.Equal(t, expectedNOnce, resp.GetSignedGossipMessage().GossipMessage.Nonce)
		break
	}
}

func TestAccept(t *testing.T) {
	comm1, port1 := newCommInstance(t, mockSecurity)
	comm2, _ := newCommInstance(t, mockSecurity)
	comm1.SetLogger(util.GetLogger(util.CommLogger, "comm1"))
	comm2.SetLogger(util.GetLogger(util.CommLogger, "comm2"))

	evenNONCESelector := func(m interface{}) bool {
		return m.(protoext.ReceivedMessage).GetSignedGossipMessage().GossipMessage.Nonce%2 == 0
	}

	oddNONCESelector := func(m interface{}) bool {
		return m.(protoext.ReceivedMessage).GetSignedGossipMessage().GossipMessage.Nonce%2 != 0
	}

	evenNONCES := comm1.Accept(evenNONCESelector)
	oddNONCES := comm1.Accept(oddNONCESelector)

	var evenResults []uint64
	var oddResults []uint64

	out := make(chan uint64)
	sem := make(chan struct{})

	readIntoSlice := func(a *[]uint64, ch <-chan protoext.ReceivedMessage) {
		for m := range ch {
			*a = append(*a, m.GetSignedGossipMessage().GossipMessage.Nonce)
			select {
			case out <- m.GetSignedGossipMessage().GossipMessage.Nonce:
			default: // avoid blocking when we stop reading from out
			}
		}
		sem <- struct{}{}
	}

	go readIntoSlice(&evenResults, evenNONCES)
	go readIntoSlice(&oddResults, oddNONCES)

	stopSend := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopSend:
				return
			default:
				comm2.Send(createSigendGossipMsg(), remotePeer(port1))
			}
		}
	}()

	waitForMessages(t, out, (DefaultSendBuffSize+DefaultRecvBuffSize)*2, "Didn't receive all messages sent")
	close(stopSend)

	comm1.Stop()
	comm2.Stop()

	<-sem
	<-sem

	t.Logf("%d even nonces received", len(evenResults))
	t.Logf("%d  odd nonces received", len(oddResults))

	require.NotEmpty(t, evenResults)
	require.NotEmpty(t, oddResults)

	remainderPredicate := func(a []uint64, rem uint64) {
		for _, n := range a {
			require.Equal(t, n%2, rem)
		}
	}

	remainderPredicate(evenResults, 0)
	remainderPredicate(oddResults, 1)
}

func TestReConnections(t *testing.T) {
	comm1, port1 := newCommInstance(t, mockSecurity)
	comm2, port2 := newCommInstance(t, mockSecurity)
	comm1.SetLogger(util.GetLogger(util.CommLogger, "comm1"))
	comm2.SetLogger(util.GetLogger(util.CommLogger, "comm2"))

	reader := func(out chan uint64, in <-chan protoext.ReceivedMessage) {
		for {
			msg := <-in
			if msg == nil {
				return
			}
			out <- msg.GetSignedGossipMessage().GossipMessage.Nonce
		}
	}

	out1 := make(chan uint64, 10)
	out2 := make(chan uint64, 10)

	go reader(out1, comm1.Accept(acceptAll))
	go reader(out2, comm2.Accept(acceptAll))

	// comm1 connects to comm2
	comm1.Send(createSigendGossipMsg(), remotePeer(port2))
	waitForMessages(t, out2, 1, "Comm2 didn't receive a message from comm1 in a timely manner")
	// comm2 sends to comm1
	comm2.Send(createSigendGossipMsg(), remotePeer(port1))
	waitForMessages(t, out1, 1, "Comm1 didn't receive a message from comm2 in a timely manner")
	comm1.Stop()

	comm1, port1 = newCommInstance(t, mockSecurity)
	comm1.SetLogger(util.GetLogger(util.CommLogger, "comm1"))
	out1 = make(chan uint64, 1)
	go reader(out1, comm1.Accept(acceptAll))
	comm2.Send(createSigendGossipMsg(), remotePeer(port1))
	waitForMessages(t, out1, 1, "Comm1 didn't receive a message from comm2 in a timely manner")
	comm1.Stop()
	comm2.Stop()
}

func TestProbe(t *testing.T) {
	comm1, port1 := newCommInstance(t, mockSecurity)
	comm1.SetLogger(util.GetLogger(util.CommLogger, "comm1"))
	defer comm1.Stop()
	comm2, port2 := newCommInstance(t, mockSecurity)
	comm2.SetLogger(util.GetLogger(util.CommLogger, "comm2"))

	time.Sleep(time.Duration(1) * time.Second)
	require.NoError(t, comm1.Probe(remotePeer(port2)))
	_, err := comm1.Handshake(remotePeer(port2))
	require.NoError(t, err)
	tempPort, _, ll := getAvailablePort(t)
	defer ll.Close()
	require.Error(t, comm1.Probe(remotePeer(tempPort)))
	_, err = comm1.Handshake(remotePeer(tempPort))
	require.Error(t, err)
	comm2.Stop()
	time.Sleep(time.Duration(1) * time.Second)
	require.Error(t, comm1.Probe(remotePeer(port2)))

	_, err = comm1.Handshake(remotePeer(port2))
	require.Error(t, err)
	comm2, port2 = newCommInstance(t, mockSecurity)
	comm2.SetLogger(util.GetLogger(util.CommLogger, "comm2"))
	defer comm2.Stop()
	time.Sleep(time.Duration(1) * time.Second)
	require.NoError(t, comm2.Probe(remotePeer(port1)))
	_, err = comm2.Handshake(remotePeer(port1))
	require.NoError(t, err)
	require.NoError(t, comm1.Probe(remotePeer(port2)))
	_, err = comm1.Handshake(remotePeer(port2))
	require.NoError(t, err)
	// Now try a deep probe with an expected PKI-ID that doesn't match
	wrongRemotePeer := remotePeer(port2)
	if wrongRemotePeer.PKIid[0] == 0 {
		wrongRemotePeer.PKIid[0] = 1
	} else {
		wrongRemotePeer.PKIid[0] = 0
	}
	_, err = comm1.Handshake(wrongRemotePeer)
	require.Error(t, err)
	// Try a deep probe with a nil PKI-ID
	endpoint := fmt.Sprintf("127.0.0.1:%d", port2)
	id, err := comm1.Handshake(&discovery.NetworkMember{ExternalEndpoint: endpoint})
	require.NoError(t, err)
	require.Equal(t, api.PeerIdentity(endpoint), id)
}

func TestPresumedDead(t *testing.T) {
	comm1, _ := newCommInstance(t, mockSecurity)
	comm1.SetLogger(util.GetLogger(util.CommLogger, "comm1"))
	comm2, port2 := newCommInstance(t, mockSecurity)
	comm2.SetLogger(util.GetLogger(util.CommLogger, "comm2"))

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		wg.Wait()
		comm1.Send(createSigendGossipMsg(), remotePeer(port2))
	}()

	ticker := time.NewTicker(time.Duration(10) * time.Second)
	acceptCh := comm2.Accept(acceptAll)
	wg.Done()
	select {
	case <-acceptCh:
		ticker.Stop()
	case <-ticker.C:
		require.Fail(t, "Didn't get first message")
	}

	comm2.Stop()
	go func() {
		for i := 0; i < 5; i++ {
			comm1.Send(createSigendGossipMsg(), remotePeer(port2))
			time.Sleep(time.Millisecond * 200)
		}
	}()

	ticker = time.NewTicker(time.Second * time.Duration(3))
	select {
	case <-ticker.C:
		require.Fail(t, "Didn't get a presumed dead message within a timely manner")
		break
	case <-comm1.PresumedDead():
		ticker.Stop()
		break
	}
}

func TestSendBadEnvelope(t *testing.T) {
	comm1, port := newCommInstance(t, mockSecurity)
	comm1.SetLogger(util.GetLogger(util.CommLogger, "comm1"))
	defer comm1.Stop()

	stream, err := establishSession(t, port)
	require.NoError(t, err)

	inc := comm1.Accept(acceptAll)

	goodMsg := createSigendGossipMsg()
	err = stream.Send(goodMsg.Envelope)
	require.NoError(t, err)

	select {
	case goodMsgReceived := <-inc:
		require.Equal(t, goodMsg.Envelope.Payload, goodMsgReceived.GetEnvelope().Payload)
	case <-time.After(time.Minute):
		require.Fail(t, "Didn't receive message within a timely manner")
		return
	}

	// Next, we corrupt a message and send it until the stream is closed forcefully from the remote peer
	start := time.Now()
	for {
		badMsg := createSigendGossipMsg()
		badMsg.Envelope.Payload = []byte{1}
		err = stream.Send(badMsg.Envelope)
		if err != nil {
			require.Equal(t, io.EOF, err)
			break
		}
		if time.Now().After(start.Add(time.Second * 30)) {
			require.Fail(t, "Didn't close stream within a timely manner")
			return
		}
	}
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

var (
	testCommConfig = CommConfig{
		DialTimeout:  300 * time.Millisecond,
		ConnTimeout:  DefaultConnTimeout,
		RecvBuffSize: DefaultRecvBuffSize,
		SendBuffSize: DefaultSendBuffSize,
	}

	mockSecurity    = &api.MockCryptoService{MockSecurityAdvisor: api.MockSecurityAdvisor{}}
	disabledMetrics = metrics.NewGossipMetrics(&disabled.Provider{}).CommMetrics

	// 从 mapper 中删除节点时，一般要删除与其之间的连接，我们这里就什么都不操作啦
	noopPurgeIdentity = func(common.PKIid, api.PeerIdentity) {}

	r *rand.Rand

	hmackey = []byte{0, 0, 0}
)

func init() {
	r = rand.New(rand.NewSource(time.Now().UnixNano()))
	mockSecurity.On("OrgByPeerIdentity", mock.Anything).Return(api.OrgIdentity{})
	hlogging.ActivateSpec("debug")
}

func acceptAll(msg interface{}) bool {
	return true
}

type commGRPC struct {
	*commImpl
	gRPCServer *comm.GRPCServer
}

func newCommInstanceWithMetrics(t *testing.T, commMetrics *metrics.CommMetrics, security *api.MockCryptoService, gRPCServer *comm.GRPCServer, certs *common.TLSCertificates, secureDialOpts api.PeerSecureDialOpts, dialOpts ...grpc.DialOption) Comm {
	endpoint := gRPCServer.Address()
	require.NotEqual(t, "", endpoint)

	id := api.PeerIdentity(endpoint)

	identityMapper := identity.NewIdentityMapper(security, id, noopPurgeIdentity, security)

	inst, err := NewCommInstance(gRPCServer.Server(), certs, identityMapper, id, secureDialOpts, security, commMetrics, testCommConfig, dialOpts...)
	require.NoError(t, err)

	go func() {
		err = gRPCServer.Start()
		require.NoError(t, err)
	}()

	return &commGRPC{
		commImpl:   inst.(*commImpl),
		gRPCServer: gRPCServer,
	}
}

func newCommInstanceWithoutMetrics(t *testing.T, security *api.MockCryptoService, gRPCServer *comm.GRPCServer, certs *common.TLSCertificates, secureDialOpts api.PeerSecureDialOpts, dialOpts ...grpc.DialOption) Comm {
	return newCommInstanceWithMetrics(t, disabledMetrics, security, gRPCServer, certs, secureDialOpts, dialOpts...)
}

func newCommInstance(t *testing.T, security *api.MockCryptoService) (comm Comm, port int) {
	port, gRPCServer, certs, secureDialOpts, dialOpts := util.CreateGRPCLayer()
	comm = newCommInstanceWithoutMetrics(t, security, gRPCServer, certs, secureDialOpts, dialOpts...)
	return comm, port
}

type msgMutator func(*protoext.SignedGossipMessage) *protoext.SignedGossipMessage

type tlsType int

const (
	none tlsType = iota
	onewayTLS
	mutualTLS
)

func handshaker(t *testing.T, port int, endpoint string, comm Comm, connMutator msgMutator, connType tlsType) <-chan protoext.ReceivedMessage {
	c := &commImpl{}
	cert := util.GenerateTLSCertificatesOrPanic()
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	if connType == mutualTLS {
		tlsCfg.Certificates = []tls.Certificate{cert} // 将客户端的证书塞入到拨号选项中
	}

	transaportCredentials := credentials.NewTLS(tlsCfg)
	dialOpt := grpc.WithTransportCredentials(transaportCredentials)
	if connType == none {
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	acceptCh := comm.Accept(acceptAll)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	target := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := grpc.DialContext(ctx, target, dialOpt, grpc.WithBlock())
	require.NoError(t, err)
	client := pbgossip.NewGossipClient(conn)
	stream, err := client.GossipStream(context.Background())
	require.NoError(t, err)

	var clientCertHash []byte
	if len(tlsCfg.Certificates) > 0 {
		clientCertHash = certHashFromRawCert(tlsCfg.Certificates[0].Certificate[0])
	}

	pkiID := common.PKIid(endpoint)
	peerIdentity := api.PeerIdentity(endpoint)
	msg, _ := c.createConnectionMsg(pkiID, clientCertHash, peerIdentity, func(msg []byte) ([]byte, error) {
		mac := hmac.New(sha256.New, hmackey)
		mac.Write(msg)
		return mac.Sum(nil), nil
	}, false)
	msg = connMutator(msg)
	stream.Send(msg.Envelope)
	envelope, err := stream.Recv()
	if err != nil {
		return acceptCh
	}
	require.NoError(t, err)
	receivedMsg, err := protoext.EnvelopeToSignedGossipMessage(envelope)
	require.NoError(t, err)
	require.Equal(t, receivedMsg.GossipMessage.GetConn().PkiId, []byte(target))
	require.Equal(t, extractCertificateHashFromContext(stream.Context()), receivedMsg.GossipMessage.GetConn().TlsCertHash)
	msg2send := createSigendGossipMsg()
	nonce := r.Uint64()
	msg2send.GossipMessage.Nonce = nonce
	go stream.Send(msg2send.Envelope)
	return acceptCh
}

func createSigendGossipMsg() *protoext.SignedGossipMessage {
	msg, _ := protoext.NoopSign(&pbgossip.GossipMessage{
		Tag:   pbgossip.GossipMessage_EMPTY,
		Nonce: r.Uint64(),
		Content: &pbgossip.GossipMessage_DataMsg{
			DataMsg: &pbgossip.DataMessage{},
		},
	})

	return msg
}

func remotePeer(port int) *discovery.NetworkMember {
	endpoint := fmt.Sprintf("127.0.0.1:%d", port)
	return &discovery.NetworkMember{
		ExternalEndpoint: endpoint,
		PKIid:            common.PKIid(endpoint),
	}
}

func getAvailablePort(t *testing.T) (port int, endpoint string, listener net.Listener) {
	var err error
	listener, err = net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	endpoint = listener.Addr().String()
	_, portStr, err := net.SplitHostPort(endpoint)
	require.NoError(t, err)
	port, err = strconv.Atoi(portStr)
	require.NoError(t, err)
	return
}

func waitForMessages(t *testing.T, msgChan chan uint64, count int, errMsg string) {
	c := 0
	waiting := true
	ticker := time.NewTicker(time.Duration(10) * time.Second)
	for waiting {
		select {
		case <-msgChan:
			c++
			if c == count {
				waiting = false
			}
		case <-ticker.C:
			waiting = false
		}
	}
	require.Equal(t, count, c, errMsg)
}

func establishSession(t *testing.T, port int) (pbgossip.Gossip_GossipStreamClient, error) {
	cert := util.GenerateTLSCertificatesOrPanic()
	secureOpts := grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
	}))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	endpoint := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := grpc.DialContext(ctx, endpoint, secureOpts, grpc.WithBlock())
	require.NoError(t, err, "%v", err)
	if err != nil {
		return nil, err
	}
	cl := pbgossip.NewGossipClient(conn)
	stream, err := cl.GossipStream(context.Background())
	require.NoError(t, err, "%v", err)
	if err != nil {
		return nil, err
	}

	clientCertHash := certHashFromRawCert(cert.Certificate[0])
	pkiID := common.PKIid([]byte{1, 2, 3})
	c := &commImpl{}
	require.NoError(t, err, "%v", err)
	msg, _ := c.createConnectionMsg(pkiID, clientCertHash, []byte{1, 2, 3}, func(msg []byte) ([]byte, error) {
		mac := hmac.New(sha256.New, hmackey)
		mac.Write(msg)
		return mac.Sum(nil), nil
	}, false)
	// Send your own connection message
	stream.Send(msg.Envelope)
	// Wait for connection message from the other side
	envelope, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	require.NotNil(t, envelope)
	return stream, nil
}
