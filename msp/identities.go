package msp

type IdentityIdentifier struct {
	// 成员服务提供商的身份标识符。
	Mspid string

	// 提供商内部的身份标识符。
	Id    string
}
