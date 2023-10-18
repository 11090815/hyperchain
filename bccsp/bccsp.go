package bccsp

import "io"

type Key interface {
	// Bytes 在允许的情况下，将密钥转换为原始的字节切片形式。
	Bytes() ([]byte, error)

	// SKI 返回该密钥的唯一标识符。
	SKI() []byte

	// Symmetric 用来标识该密钥是否是对称密钥，如果是的话，则返回 true，否则返回 false。
	Symmetric() bool

	// IsPrivate 用来标识该密钥是否是私钥，如果是的话，则返回 true，否则返回 false。
	IsPrivate() bool

	// PublicKey 返回非对称密钥中的公钥，如果该密钥是对称密钥，调用该方法会返回错误。
	PublicKey() (Key, error)
}

// EncrypterOpts 实际上是一个空的 interface{}。
type EncrypterOpts interface{}

type AESCBCPKCS7ModeOpts struct {
	IV   []byte
	PRNG io.Reader
}

// DecrypterOpts 实际上是一个空的 interface{}。
type DecrypterOpts interface{}
