package gossip

import (
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/common/channelconfig"
	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/11090815/hyperchain/common/policies"
	"github.com/11090815/hyperchain/gossip/api"
	"github.com/11090815/hyperchain/gossip/common"
	"github.com/11090815/hyperchain/internal/pkg/identity"
	"github.com/11090815/hyperchain/msp"
	pbcommon "github.com/11090815/hyperchain/protos-go/common"
	"github.com/11090815/hyperchain/protoutil"
)

var mcsLogger = hlogging.MustGetLogger("peer.gossip.msp_message_crypto_service")

type Hasher interface {
	Hash(msg []byte, opts bccsp.HashOpts) (hash []byte, err error)
}

type ChannelConfigGetter func(cid string) channelconfig.Resources

type MSPMessageCryptoService struct {
	channelPolicyManagerGetter policies.ChannelPolicyManagerGetter
	localSigner                identity.SignerSerializer
	deserializer               DeserializersManager
	hasher                     Hasher
	channelConfigGetter        ChannelConfigGetter
}

// GetPKIidOfCert 根据给定的 api.PeerIdentity 计算 common.PKIid。
func (mmcs *MSPMessageCryptoService) GetPKIidOfCert(peerIdentity api.PeerIdentity) common.PKIid {
	if len(peerIdentity) == 0 {
		mcsLogger.Error("Invalid peer identity, it must be not empty.")
		return nil
	}

	sid, err := mmcs.deserializer.Deserialize(peerIdentity)
	if err != nil {
		mcsLogger.Errorf("Failed deserializing peer identity material: [%s]", err.Error())
		return nil
	}

	raw := append([]byte(sid.Mspid), sid.IdBytes...)

	digest, err := mmcs.hasher.Hash(raw, &bccsp.SHA256Opts{})
	if err != nil {
		mcsLogger.Error("Failed computing digest of msp id and identity cert: [%s]", err.Error())
		return nil
	}

	return digest
}

func (mmcs *MSPMessageCryptoService) VerifyBlockAttestation(channelID string, block *pbcommon.Block) error {
	if block == nil {
		return fmt.Errorf("invalid block on channel [%s], it should not be empty", channelID)
	}
	if block.Header == nil {
		return fmt.Errorf("invalid block on channel [%s], block header should not be empty", channelID)
	}

	if block.Metadata == nil || len(block.Metadata.Metadata) == 0 {
		return fmt.Errorf("the no.%d block on channel [%s] does not have metadata", block.Header.Number, channelID)
	}

	// return mmcs.
}

func (mmcs *MSPMessageCryptoService) Sign(message []byte) ([]byte, error) {
	return mmcs.localSigner.Sign(message)
}

// Verify 验证签名在指定 identity 下是否正确。
func (mmcs *MSPMessageCryptoService) Verify(peerIdentity api.PeerIdentity, signature, message []byte) error {
	identity, channelID, err := mmcs.getValidatedIdentity(peerIdentity)
	if err != nil {
		mcsLogger.Errorf("Failed getting validated identity from peer identity: [%s]", err.Error())
		return err
	}

	if len(channelID) == 0 {
		return identity.Verify(message, signature)
	}

	return mmcs.VerifyByChannel(channelID, peerIdentity, signature, message)
}

func (mmcs *MSPMessageCryptoService) VerifyByChannel(channelID common.ChannelID, peerIdentity api.PeerIdentity, signature, message []byte) error {
	if len(peerIdentity) == 0 {
		return errors.New("invalid peer identity, it must be not empty")
	}

	cpm := mmcs.channelPolicyManagerGetter.Manager(channelID.String())
	if cpm == nil {
		return fmt.Errorf("could not get policy manager for channel [%s]", channelID.String())
	}

	mcsLogger.Debugf("Got policy manager for channel [%s].", channelID.String())

	policy, flag := cpm.GetPolicy(policies.ChannelApplicationReaders)
	if flag {
		mcsLogger.Debugf("Got reader policy for channel [%s].", channelID.String())
	} else {
		mcsLogger.Debugf("Got default reader policy for channel [%s].", channelID.String())
	}

	return policy.EvaluateSignedData([]*protoutil.SignedData{{Data: message, Identity: peerIdentity, Signature: signature}})
}

// ValidateIdentity 如果给定的 identity 是本地 msp 管理的，则利用本地 msp 对该身份进行验证，否则
// 遍历所有通道的 msp，检查该身份是否由这些 msp 管理的，是的话，则利用这些 msp 对身份进行验证。
func (mmcs *MSPMessageCryptoService) ValidateIdentity(peerIdentity api.PeerIdentity) error {
	_, _, err := mmcs.getValidatedIdentity(peerIdentity)
	return err
}

// Expiration 返回身份的过期时间。
func (mmcs *MSPMessageCryptoService) Expiration(peerIdentity api.PeerIdentity) (time.Time, error) {
	id, _, err := mmcs.getValidatedIdentity(peerIdentity)
	if err != nil {
		return time.Time{}, fmt.Errorf("unable to extract msp.Identity from peer identity: [%s]", err.Error())
	}
	return id.ExpiresAt(), nil
}

func (mmcs *MSPMessageCryptoService) getValidatedIdentity(peerIdentity api.PeerIdentity) (msp.Identity, common.ChannelID, error) {
	if len(peerIdentity) == 0 {
		mcsLogger.Error("Invalid peer identity, it must be not empty.")
		return nil, nil, errors.New("invalid peer identity, it must be not empty")
	}

	sid, err := mmcs.deserializer.Deserialize(peerIdentity)
	if err != nil {
		mcsLogger.Errorf("Failed deserializing peer identity material: [%s].", err.Error())
		return nil, nil, fmt.Errorf("failed deserializing identity: [%s]", err.Error())
	}

	localDeserializer := mmcs.deserializer.GetLocalDeserializer()
	identity, err := localDeserializer.DeserializeIdentity(peerIdentity)
	if err == nil {
		if err = localDeserializer.IsWellFormed(sid); err != nil {
			return nil, nil, fmt.Errorf("identity is not well formed: [%s]", err.Error())
		}

		if identity.GetMSPIdentifier() == mmcs.deserializer.GetLocalMSPIdentifier() {
			return identity, nil, identity.Validate()
		}
	}

	for channelID, mspManager := range mmcs.deserializer.GetChannelDeserializers() {
		identity, err := mspManager.DeserializeIdentity(peerIdentity)
		if err != nil {
			// 有可能 identity 里存储的 msp id 和 mspManager 指向的 msp id 不一样，这样的话，err 不为 nil。
			mcsLogger.Errorf("Failed deserializing identity: [%s].", err.Error())
			continue
		}

		if err = mspManager.IsWellFormed(sid); err != nil {
			return nil, nil, fmt.Errorf("identity is not well formed: [%s]", err.Error())
		}

		if err = identity.Validate(); err != nil {
			mcsLogger.Errorf("Failed validating identity: [%s].", err.Error())
			continue
		}

		mcsLogger.Debugf("Validation peer identity [%s] successfully on channel [%s].", peerIdentity, channelID)

		return identity, common.ChannelID(channelID), nil
	}

	return nil, nil, fmt.Errorf("peer identity %s cannot be validated, no msp is able to do that", peerIdentity)
}

func (mmcs *MSPMessageCryptoService) verifyHeaderAndMetadata(channelID string, block *pbcommon.Block) error {
	cpm := mmcs.channelPolicyManagerGetter.Manager(channelID)
	if cpm == nil {
		return fmt.Errorf("could not get policy manager for channel [%s]", channelID)
	}
	mcsLogger.Debugf("Got policy manager for channel [%s]", channelID)

	policy, ok := cpm.GetPolicy(policies.BlockValidation)
	if ok {
		mcsLogger.Debugf("Got block validation policy for channel [%s].", channelID.String())
	} else {
		mcsLogger.Debugf("Got default block validation policy for channel [%s].", channelID.String())
	}

	channelConfig := mmcs.channelConfigGetter(channelID)
	
}
