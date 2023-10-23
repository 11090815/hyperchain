package crypto

import "github.com/11090815/hyperchain/bccsp"

const NonceSize = 24

func GetRandomNonce() ([]byte, error) {
	return bccsp.GetRandomBytes(NonceSize)
}
