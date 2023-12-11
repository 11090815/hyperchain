package protoext

import (
	"encoding/hex"
	"fmt"

	pbgossip "github.com/11090815/hyperchain/protos-go/gossip"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
	"google.golang.org/protobuf/proto"
)

func MemberToString(m *pbgossip.Member) string {
	return fmt.Sprintf("Membership Endpoint: %s, PKI-id: %s", m.Endpoint, hex.EncodeToString(m.PkiId))
}

func MembershipResponseToString(mr *pbgossip.MembershipResponse) string {
	return fmt.Sprintf("MembershipResponse with alive: %d, dead: %d", len(mr.Alive), len(mr.Dead))
}

func AliveMessageToString(am *pbgossip.AliveMessage) string {
	if am.Membership == nil {
		return "nil Membership"
	}

	var identity string
	serializedIdentity := &pbmsp.SerializedIdentity{}
	if err := proto.Unmarshal(am.Identity, serializedIdentity); err == nil {
		identity = serializedIdentity.Mspid + string(serializedIdentity.IdBytes)
	}
	return fmt.Sprintf("AliveMessage: %s, Identity: %s, Timestamp: %v", MemberToString(am.Membership), identity, am.Timestamp)
}

func PayloadToString(payload *pbgossip.Payload) string {
	return fmt.Sprintf("Block: {Data: %dbytes, SeqNum: %d}", len(payload.Data), payload.SeqNum)
}

func DataUpdateToString(du *pbgossip.DataUpdate) string {
	msgType := pbgossip.PullMsgType_name[int32(du.MsgType)]
	return fmt.Sprintf("Type: %s, items: %dbytes, nonce :%d", msgType, len(du.Data), du.Nonce)
}

func StateInfoSnapshotToString(sis *pbgossip.StateInfoSnapshot) string {
	return fmt.Sprintf("StateInfoSnapshot with %d elements", len(sis.Elements))
}

func StateInfoPullRequestToString(sipr *pbgossip.StateInfoPullRequest) string {
	return fmt.Sprintf("StateInfoPullRequest ChannelMAC: %s", hex.EncodeToString(sipr.Channel_MAC))
}

func StateInfoToString(si *pbgossip.StateInfo) string {
	return fmt.Sprintf("StateInfo Timestamp: %v, PKI-id: %s, ChannelMAC: %s, Properties: %v", si.Timestamp, hex.EncodeToString(si.PkiId), hex.EncodeToString(si.Channel_MAC), si.Properties)
}

func MembershipRequestToString(mr *pbgossip.MembershipRequest) string {
	if mr.SelfInformation == nil {
		return ""
	}
	sgm, err := EnvelopeToGossipMessage(mr.SelfInformation)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("Membership request with self information of %s", sgm.String())
}

func DataDigestToString(dd *pbgossip.DataDigest) string {
	digests := formatDigests(dd.MsgType, dd.Digests)
	return fmt.Sprintf("DataDigest Nonce: %d, MsgType: %s, Digests: %v", dd.Nonce, dd.MsgType, digests)
}

func DataRequestToString(dataReq *pbgossip.DataRequest) string {
	digests := formatDigests(dataReq.MsgType, dataReq.Digests)
	return fmt.Sprintf("DataRequest Nonce: %d, MsgType: %s, Digests: %v", dataReq.Nonce, dataReq.MsgType, digests)
}

func LeadershipMessageToString(lm *pbgossip.LeadershipMessage) string {
	return fmt.Sprintf("LeadershipMessage PKI-id: %s, Timestamp: %v, IsDeclaration: %v", hex.EncodeToString(lm.PkiId), lm.Timestamp, lm.IsDeclaration)
}

func RemotePvtDataResponseToString(res *pbgossip.RemotePvtDataResponse) string {
	elements := make([]string, len(res.Elements))
	for i, element := range res.Elements {
		elements[i] = fmt.Sprintf("%s with %dbytes payload", element.Digest.String(), len(element.Payload))
	}
	return fmt.Sprintf("%v", elements)
}

func formatDigests(msgType pbgossip.PullMsgType, givenDigests [][]byte) []string {
	var strs []string
	switch msgType {
	case pbgossip.PullMsgType_BLOCK_MSG:
		for _, digest := range givenDigests {
			strs = append(strs, string(digest))
		}
	case pbgossip.PullMsgType_IDENTITY_MSG:
		for _, digest := range givenDigests {
			strs = append(strs, hex.EncodeToString(digest))
		}
	}
	return strs
}
