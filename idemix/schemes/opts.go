package schemes

import (
	"crypto"

	"github.com/11090815/hyperchain/bccsp"
)

type IdemixCredentialRequestSignerOpts struct {
	// 证书中包含的属性的索引列表。
	Attributes []int

	// 签发者的公钥。
	IssuerPK bccsp.Key

	// IssuerNonce 由签发人生成，客户端使用它来生成凭据请求。签发人收到凭据请求后，会检查 nonce 是否相同。
	IssuerNonce []byte

	// 被使用的哈希函数。
	H crypto.Hash
}

func (o *IdemixCredentialRequestSignerOpts) HashFunc() crypto.Hash {
	return o.H
}

func (o *IdemixCredentialRequestSignerOpts) IssuerPublicKey() bccsp.Key {
	return o.IssuerPK
}
