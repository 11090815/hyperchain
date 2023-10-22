package sw

import (
	"hash"

	"github.com/11090815/hyperchain/bccsp"
)

type Hasher interface {
	Hash(msg []byte, opts bccsp.HashOpts) ([]byte, error)
	GetHash(opts bccsp.HashOpts) (h hash.Hash, err error)
}

type hasher struct {
	hash func() hash.Hash
}

func (c *hasher) Hash(msg []byte, opts bccsp.HashOpts) ([]byte, error) {
	h := c.hash()
	h.Write(msg)
	return h.Sum(nil), nil
}

func (c *hasher) GetHash(opts bccsp.HashOpts) (hash.Hash, error) {
	return c.hash(), nil
}
