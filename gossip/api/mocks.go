package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/11090815/hyperchain/gossip/common"
	pbcommon "github.com/11090815/hyperchain/protos-go/common"
	"github.com/stretchr/testify/mock"
)

type MockSecurityAdvisor struct {
	mock.Mock
}

func (msa *MockSecurityAdvisor) OrgByPeerIdentity(peerIdentity PeerIdentity) OrgIdentity {
	res := msa.Called(peerIdentity)

	var oi OrgIdentity
	if fn, ok := res.Get(0).(func(PeerIdentity) OrgIdentity); ok {
		oi = fn(peerIdentity)
	} else {
		if res.Get(0) != nil {
			oi = res.Get(0).(OrgIdentity)
		}
	}

	return oi
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type MockCryptoService struct {
	MockSecurityAdvisor
}

func (mcs *MockCryptoService) Expiration(peerIdentity PeerIdentity) (time.Time, error) {
	return time.Now().Add(time.Hour), nil
}

func (*MockCryptoService) ValidateIdentity(peerIdentity PeerIdentity) error {
	return nil
}

func (*MockCryptoService) GetPKIidOfCert(peerIdentity PeerIdentity) common.PKIid {
	return common.PKIid(peerIdentity)
}

func (*MockCryptoService) VerifyBlock(channelID common.ChannelID, seqNum uint64, block *pbcommon.Block) error {
	return nil
}

func (*MockCryptoService) VerifyBlockAttestation(channelID common.ChannelID, block *pbcommon.Block) error {
	return nil
}

func (*MockCryptoService) Sign(msg []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte{0, 0, 0})
	mac.Write(msg)
	return mac.Sum(nil), nil
}

func (*MockCryptoService) Verify(peerIdentity PeerIdentity, signature, message []byte) error {
	mac := hmac.New(sha256.New, []byte{0, 0, 0})
	mac.Write(message)
	expected := mac.Sum(nil)
	if !bytes.Equal(signature, expected) {
		return fmt.Errorf("wrong signature")
	}
	return nil
}

func (*MockCryptoService) VerifyByChannel(common.ChannelID, PeerIdentity, []byte, []byte) error {
	return nil
}
