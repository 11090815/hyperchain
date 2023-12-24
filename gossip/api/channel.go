package api

type SecurityAdvisor interface {
	// 根据提供的 PeerIdentity 返回 OrgIdentity。
	OrgByPeerIdentity(PeerIdentity) OrgIdentity
}
