package bccsp

import (
	"hash"
)

type Hasher interface {
	Hash(msg []byte, opts HashOpts) ([]byte, error)
	GetHash(opts HashOpts) (h hash.Hash, err error)
}

type hasher struct {
	hash func() hash.Hash
}

func (c *hasher) Hash(msg []byte, opts HashOpts) ([]byte, error) {
	h := c.hash()
	h.Write(msg)
	return h.Sum(nil), nil
}

func (c *hasher) GetHash(opts HashOpts) (hash.Hash, error) {
	return c.hash(), nil
}
