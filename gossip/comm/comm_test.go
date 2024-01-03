package comm

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"strconv"
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
	// signer := func(msg []byte) ([]byte, error) {
	// 	mac := hmac.New(sha256.New, hmackey)
	// 	mac.Write(msg)
	// 	return mac.Sum(nil), nil
	// }

	mutator := func(msg *protoext.SignedGossipMessage) *protoext.SignedGossipMessage {
		return msg
	}

	// assertPositivePath := func(msg protoext.ReceivedMessage, endpoint string) {
	// 	expectedPKIid := common.PKIid(endpoint)
	// 	expectedIdentity := api.PeerIdentity(endpoint)
	// 	require.Equal(t, expectedPKIid, msg.GetConnectionInfo().PKIid)
	// 	require.Equal(t, expectedIdentity, msg.GetConnectionInfo().Identity)
	// 	require.NotNil(t, msg.GetConnectionInfo().Auth)
	// 	sig, _ := mockSecurity.Sign(msg.GetConnectionInfo().Auth.SignedData)
	// 	require.Equal(t, sig, msg.GetConnectionInfo().Auth.Signature)
	// }

	// 1. 不设置 TLS
	port, endpoint, listener := getAvailablePort(t)
	s := grpc.NewServer()
	id := api.PeerIdentity(endpoint)
	idMapper := identity.NewIdentityMapper(mockSecurity, id, noopPurgeIdentity, mockSecurity)
	comm, err := NewCommInstance(s, nil, idMapper, id, func() []grpc.DialOption {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}, mockSecurity, disabledMetrics, testCommConfig)
	require.NoError(t, err)
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

	t.Logf("%T", msg.GetSignedGossipMessage().GossipMessage.Content)
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
		tlsCfg.Certificates = []tls.Certificate{cert}
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
	msg, _ := c.createConnectionMsg(pkiID, clientCertHash, []byte(endpoint), func(msg []byte) ([]byte, error) {
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
