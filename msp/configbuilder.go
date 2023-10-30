package msp

type Configuration struct {
	OrganizationalUnitIdentifiers []*OrganizationalUnitIdentifiersConfiguration `yaml:"OrganizationalUnitIdentifiers,omitempty"`
	NodeOUs                       *NodeOUs                                      `yaml:"NodeOUs,omitempty"`
}

// OrganizationalUnitIdentifiersConfiguration 用来代表一个 OU，OrganizationalUnitIdentifiersConfiguration 结构体内
// 有两个配置变量：Certificate 指向了存储根证书或者中间证书的路径；OrganizationalUnitIdentifier 代表 OU 的名字。
type OrganizationalUnitIdentifiersConfiguration struct {
	// Certificate 指向根证书或者中间证书的存放路径。
	Certificate string `yaml:"Certificate,omitempty"`
	// OrganizationalUnitIdentifier 是 OU 的名字，这没什么可说的。
	OrganizationalUnitIdentifier string `yaml:"OrganizationalUnitIdentifier,omitempty"`
}

// NodeOUs：
//   - ClientOUIdentifier 规定了如何通过 OU 识别 clients；
//   - PeerOUIdentifier 规定了如何通过 OU 识别 peers；
//   - AdminOUIdentifier 规定了如何通过 OU 识别 admins；
//   - OrdererOUIdentifier 规定了如何通过 OU 识别 orderers。
type NodeOUs struct {
	Enable bool `yaml:"Enable,omitempty"`
	// ClientOUIdentifier 规定了如何通过 OU 识别 clients。
	ClientOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"ClientOUIdentifier,omitempty"`
	// PeerOUIdentifier 规定了如何通过 OU 识别 peers。
	PeerOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"PeerOUIdentifier,omitempty"`
	// AdminOUIdentifier 规定了如何通过 OU 识别 admins。
	AdminOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"AdminOUIdentifier,omitempty"`
	// OrdererOUIdentifier 规定了如何通过 OU 识别 orderers。
	OrdererOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"OrdererOUIdentifier,omitempty"`
}
