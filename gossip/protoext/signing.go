package protoext

import (
	"errors"
	"fmt"

	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
	"google.golang.org/protobuf/proto"
)

// SignerFunc 给定一个消息 msg，对其进行签名，得到签名。
type SignerFunc func(msg []byte) ([]byte, error)

// VerifierFunc 根据给定的 peer 身份验证签名的正确性。
type VerifierFunc func(peerIdentity []byte, signature []byte, message []byte) error

type SignedGossipMessage struct {
	Envelope      *pbgossip.Envelope
	GossipMessage *pbgossip.GossipMessage
}

// Sign:
//  1. payload = proto.Marshal(sgm.GossipMessage)
//  2. signature = signer(payload)
//  3. 重组 Envelope：Envelope{payload, signature}
func (sgm *SignedGossipMessage) Sign(signer SignerFunc) (*pbgossip.Envelope, error) {
	var se *pbgossip.SecretEnvelope
	if sgm.Envelope != nil {
		se = sgm.Envelope.SecretEnvelope
	}
	sgm.Envelope = nil
	payload, err := proto.Marshal(sgm.GossipMessage)
	if err != nil {
		return nil, err
	}
	signature, err := signer(payload)
	if err != nil {
		return nil, err
	}

	envelope := &pbgossip.Envelope{
		Payload:        payload,
		Signature:      signature,
		SecretEnvelope: se,
	}
	sgm.Envelope = envelope
	return envelope, nil
}

func (sgm *SignedGossipMessage) Verify(peerIdentity []byte, verify VerifierFunc) error {
	if sgm.Envelope == nil {
		return errors.New("missing envelope")
	}

	if len(sgm.Envelope.Payload) == 0 {
		return errors.New("empty payload")
	}

	if len(sgm.Envelope.Signature) == 0 {
		return errors.New("empty signature")
	}

	if err := verify(peerIdentity, sgm.Envelope.Signature, sgm.Envelope.Payload); err != nil {
		return err
	}

	if sgm.Envelope.SecretEnvelope != nil {
		if len(sgm.Envelope.SecretEnvelope.Payload) == 0 {
			return errors.New("empty payload in secret envelope")
		}
		if len(sgm.Envelope.SecretEnvelope.Signature) == 0 {
			return errors.New("empty signature in secret envelope")
		}
		return verify(peerIdentity, sgm.Envelope.SecretEnvelope.Signature, sgm.Envelope.SecretEnvelope.Payload)
	}

	return nil
}

// IsSigned 返回 SignedGossipMessage 里的 Envelope 是否有签名。
func (sgm *SignedGossipMessage) IsSigned() bool {
	return sgm.Envelope != nil && sgm.Envelope.Payload != nil && sgm.Envelope.Signature != nil
}

func (sgm *SignedGossipMessage) String() string {
	envelope := "No envelope"
	if sgm.Envelope != nil {
		var secretEnvelope string
		if sgm.Envelope.SecretEnvelope != nil {
			payloadLen := len(sgm.Envelope.SecretEnvelope.Payload)
			signatureLen := len(sgm.Envelope.SecretEnvelope.Signature)
			secretEnvelope = fmt.Sprintf("Secret payload: %d bytes, Secret signature: %d bytes", payloadLen, signatureLen)
		}
		envelope = fmt.Sprintf("Payload: %d bytes, Signature: %d bytes, %s", len(sgm.Envelope.Payload), len(sgm.Envelope.Signature), secretEnvelope)
	}

	gossipMessage := "No gossip message"
	if sgm.GossipMessage != nil {
		var isSimpleMsg bool
		if sgm.GossipMessage.GetStateResponse() != nil {
			gossipMessage = fmt.Sprintf("StateResponse with %d payloads", len(sgm.GossipMessage.GetStateResponse().Payloads))
		} else if sgm.GossipMessage.GetDataMsg() != nil && sgm.GossipMessage.GetDataMsg().Payload != nil {
			// 区块消息不为空
			gossipMessage = PayloadToString(sgm.GossipMessage.GetDataMsg().Payload)
		} else if sgm.GossipMessage.GetDataUpdate() != nil {
			// 更新区块的消息不为空
			gossipMessage = fmt.Sprintf("DataUpdate: %s", DataUpdateToString(sgm.GossipMessage.GetDataUpdate()))
		} else if sgm.GossipMessage.GetMemRes() != nil {
			gossipMessage = MembershipResponseToString(sgm.GossipMessage.GetMemRes())
		} else if sgm.GossipMessage.GetStateSnapshot() != nil {
			gossipMessage = StateInfoSnapshotToString(sgm.GossipMessage.GetStateSnapshot())
		} else if sgm.GossipMessage.GetPrivateRes() != nil {
			gossipMessage = RemotePvtDataResponseToString(sgm.GossipMessage.GetPrivateRes())
		} else if sgm.GossipMessage.GetAliveMsg() != nil {
			gossipMessage = AliveMessageToString(sgm.GossipMessage.GetAliveMsg())
		} else if sgm.GossipMessage.GetMemReq() != nil {
			gossipMessage = MembershipRequestToString(sgm.GossipMessage.GetMemReq())
		} else if sgm.GossipMessage.GetStateInfoPullReq() != nil {
			gossipMessage = StateInfoPullRequestToString(sgm.GossipMessage.GetStateInfoPullReq())
		} else if sgm.GossipMessage.GetStateInfo() != nil {
			gossipMessage = StateInfoToString(sgm.GossipMessage.GetStateInfo())
		} else if sgm.GossipMessage.GetDataDig() != nil {
			gossipMessage = DataDigestToString(sgm.GossipMessage.GetDataDig())
		} else if sgm.GossipMessage.GetDataReq() != nil {
			gossipMessage = DataRequestToString(sgm.GossipMessage.GetDataReq())
		} else if sgm.GossipMessage.GetLeadershipMsg() != nil {
			gossipMessage = LeadershipMessageToString(sgm.GossipMessage.GetLeadershipMsg())
		} else {
			gossipMessage = sgm.GossipMessage.String()
			isSimpleMsg = true
		}
		if !isSimpleMsg {
			desc := fmt.Sprintf("Channel: %s, nonce: %d, tag: %s", string(sgm.GossipMessage.Channel), sgm.GossipMessage.Nonce, sgm.GossipMessage.Tag.String())
			gossipMessage = fmt.Sprintf("%s %s", desc, gossipMessage)
		}
	}

	return fmt.Sprintf("GossipMessage: %s, Envelope: %s", gossipMessage, envelope)
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

// SignSecret 对秘密消息 Secret 进行签名，并将签名结果填充到 Envelope 的 SecretEnvelope 里。
func SignSecret(envelope *pbgossip.Envelope, signer SignerFunc, secret *pbgossip.Secret) error {
	payload, err := proto.Marshal(secret)
	if err != nil {
		return err
	}
	signature, err := signer(payload)
	if err != nil {
		return err
	}

	envelope.SecretEnvelope = &pbgossip.SecretEnvelope{
		Payload:   payload,
		Signature: signature,
	}

	return nil
}

// NoopSign 构建 SignedGossipMessage 结构体：
//
//	type SignedGossipMessage struct {
//		Envelope      *pbgossip.Envelope
//		GossipMessage *pbgossip.GossipMessage
//	}
//
// 所构建的结构体中，GossipMessage 就是 NoopSign 函数给定的 GossipMessage 参数，原封不动；
// 而 Envelope 则是通过实例化得来的，Envelope 结构体中定义了三个字段：Payload、Signature、SecretEnvelope，
// NoopSign 函数只会计算其中的 Payload 字段的值，即 proto.Marshal(给定的 GossipMessage)，对于 Signature 和
// SecretEnvelope 两个字段，则直接将其设置为空。
func NoopSign(gm *pbgossip.GossipMessage) (*SignedGossipMessage, error) {
	sgm := &SignedGossipMessage{
		GossipMessage: gm,
	}

	signer := func(msg []byte) ([]byte, error) {
		return nil, nil
	}
	sgm.Sign(signer)

	return sgm, nil
}

// EnvelopeToSignedGossipMessage Envelope.Payload 存储的是基于 GossipMessage 的 protobuf 编码数据，对其进行反序列化即可获得 GossipMessage。
func EnvelopeToSignedGossipMessage(envelope *pbgossip.Envelope) (*SignedGossipMessage, error) {
	if envelope == nil {
		return nil, errors.New("nil envelope")
	}

	gm := &pbgossip.GossipMessage{}
	if err := proto.Unmarshal(envelope.Payload, gm); err != nil {
		return nil, fmt.Errorf("failed converting Envelope to SignedGossipMessage: [%s]", err.Error())
	}
	return &SignedGossipMessage{GossipMessage: gm, Envelope: envelope}, nil
}

// InternalEndpoint SecretEnvelope.Payload 存储的是基于 Secret 的 protobuf 编码数据，对其进行反序列化即可获得 Secret。
func InternalEndpoint(se *pbgossip.SecretEnvelope) string {
	if se == nil {
		return ""
	}
	secret := &pbgossip.Secret{}
	if err := proto.Unmarshal(se.Payload, secret); err != nil {
		return ""
	}
	return secret.GetInternalEndpoint()
}
