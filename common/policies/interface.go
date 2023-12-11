package policies

import (
	"github.com/11090815/hyperchain/msp"
	"github.com/11090815/hyperchain/protoutil"
)

// ChannelPolicyManagerGetter 用于访问给定通道的策略管理器。
type ChannelPolicyManagerGetter interface {
	// 返回与对应通道关联的策略管理器。
	Manager(channelID string) Manager
}

type Manager interface {
	// GetPolicy 返回一个策略，如果是请求的策略，则返回 true，如果是默认策略，则返回 false。
	GetPolicy(path string) (Policy, bool)

	// Manager 返回给定路径的子策略管理器以及该路径是否存在。
	Manager(path []string) (Manager, bool)
}

type Policy interface {
	// EvaluateSignedData 以一组 protoutil.SignedData 为输入，进行一下操作：
	//	1. 验证签名是否合法；
	//	2. 进行签名的身份是否满足策略。
	EvaluateSignedData(signatures []*protoutil.SignedData) error

	// 以一组身份作为输入，验证这些身份是否满足策略。
	EvaluateIdentities(identities []msp.Identity) error
}
