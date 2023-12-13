package protoutil

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/11090815/hyperchain/common/util"
	pbcommon "github.com/11090815/hyperchain/protos-go/common"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
	"google.golang.org/protobuf/proto"
)

type BlockVerifierFunc func(header *pbcommon.BlockHeader, metadata *pbcommon.BlockMetadata) error

type policy interface {
	EvaluateSignedData(signatures []*SignedData) error
}

func GetChannelIDFromBlock(block *pbcommon.Block) (string, error) {
	if block == nil || block.Data == nil || block.Data.Data == nil || len(block.Data.Data) == 0 {
		return "", errors.New("failed retrieving channel id, block is empty")
	}

	envelope, err := GetEnvelopeFromBlock(block.Data.Data[0])
	if err != nil {
		return "", fmt.Errorf("failed retrieving channel id: [%s]", err.Error())
	}

	payload, err := UnmarshalPayload(envelope.Payload) // 包含消息产生者的身份和消息本身
	if err != nil {
		return "", fmt.Errorf("failed retrieving channel id: [%s]", err.Error())
	}

	if payload.Header == nil {
		return "", errors.New("failed retrieving channel id, the header of the payload of the first data in block is nil")
	}
	ch, err := UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return "", fmt.Errorf("failed retrieving channel id: [%s]", err.Error())
	}
	return ch.ChannelId, nil
}

func BlockDataHash(data *pbcommon.BlockData) []byte {
	sum := sha256.Sum256(bytes.Join(data.Data, nil))
	return sum[:]
}

// BlockSignatureVerifier 方法返回一个函数 func(header *pbcommon.BlockHeader, metadata *pbcommon.BlockMetadata) error，
// 此函数接收两个参数：区块头和区块元数据，BlockSignatureVerifier 方法构造返回的函数的执行逻辑：我们首先提取区块元数据中的第一
// 条元数据，该条元数据里存储着所有签名者对区块的签名信息，我们需要做的是，根据元数据提供的信息，我们需要构造被签名的消息，被签名
// 的消息由以下三条消息拼接构成：元数据的值 metadata.Value || 签名者在共识组内的编号或者签名者的身份信息 || 区块头信息；其次，我
// 们需要找到签名者的身份信息（用 x509 证书表示的身份）；最后逐一获取元数据里的签名 metadata.Signatures，并将每个签名和前面获取到
// 的签名消息和签名者构造成一个 SignedData 结构体，若干 SignedData 结构体实例作为 policy.EvaluateSignedData 方法的唯一入参，逐一
// 检查这些签名的合法性。
func BlockSignatureVerifier(bftEnabled bool, consenters []*pbcommon.Consenter, policy policy) BlockVerifierFunc {
	return func(header *pbcommon.BlockHeader, metadata *pbcommon.BlockMetadata) error {
		if len(metadata.GetMetadatas()) < int(pbcommon.BlockMetadataIndex_SIGNATURES)+1 {
			// 元数据里至少第一条数据存储的是签名数据
			return errors.New("no signature in block metadata")
		}

		md := &pbcommon.Metadata{}
		if err := proto.Unmarshal(metadata.GetMetadatas()[pbcommon.BlockMetadataIndex_SIGNATURES], md); err != nil {
			return err
		}

		var signatures []*SignedData
		for _, metadataSignature := range md.Signatures {
			var signerIdentity []byte
			var signedPayload []byte
			if bftEnabled && len(metadataSignature.GetSignatureHeader()) == 0 && len(metadataSignature.GetIdentifierHeader()) > 0 {
				identifierHeader, err := UnmarshalIdentifierHeader(metadataSignature.GetIdentifierHeader())
				if err != nil {
					return fmt.Errorf("failed unmarshalling identifier header for no.%d block: [%s]", header.Number, err.Error())
				}
				id := identifierHeader.GetIdentifier() // 获取共识节点的编号
				signerIdentity = searchConsenterIdentityByID(consenters, id)
				if len(signerIdentity) == 0 {
					// 没找到生成签名的共识节点
					continue
				}
				signedPayload = util.ConcatenateBytes(md.Value, metadataSignature.IdentifierHeader, BlockHeaderBytes(header))
			} else {
				signatureHeader, err := UnmarshalSignatureHeader(metadataSignature.GetSignatureHeader())
				if err != nil {
					return fmt.Errorf("failed unmarshalling signature header for no.%d block: [%s]", header.Number, err.Error())
				}
				signedPayload = util.ConcatenateBytes(md.Value, metadataSignature.GetSignatureHeader(), BlockHeaderBytes(header))
				signerIdentity = signatureHeader.Creator
			}

			signatures = append(signatures,
				&SignedData{
					Identity:  signerIdentity,
					Data:      signedPayload,
					Signature: metadataSignature.Signature,
				})
		}

		return policy.EvaluateSignedData(signatures)
	}
}

func BlockHeaderBytes(bh *pbcommon.BlockHeader) []byte {
	return MarshalOrPanic(bh)
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

func searchConsenterIdentityByID(consenters []*pbcommon.Consenter, id uint32) []byte {
	for _, consenter := range consenters {
		if consenter.Id == id {
			return MarshalOrPanic(&pbmsp.SerializedIdentity{
				Mspid:   consenter.MspId,
				IdBytes: consenter.Identity,
			})
		}
	}
	return nil
}
