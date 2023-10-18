package sw

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/11090815/hyperchain/bccsp"
)

type aescbcpkcs7Encryptor struct{}

func (e *aescbcpkcs7Encryptor) Encrypt(key bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	switch o := opts.(type) {
	case *bccsp.AESCBCPKCS7ModeOpts:
		if len(o.IV) != 0 {
			return AESCBCPKCS7EncryptWithIV(o.IV, key.(*aesPrivateKey).privateKey, plaintext)
		} else if o.PRNG != nil {
			return AESCBCPKCS7EncryptWithRand(o.PRNG, key.(*aesPrivateKey).privateKey, plaintext)
		}
		return AESCBCPKCS7Encrypt(key.(*aesPrivateKey).privateKey, plaintext)
	case bccsp.AESCBCPKCS7ModeOpts:
		return e.Encrypt(key, plaintext, &o)
	default:
		return nil, fmt.Errorf("invalid option, want [bccsp.AESCBCPKCS7ModeOpts], but got [%T]", o)
	}
}

type aescbcpkcs7Decryptor struct{}

func (*aescbcpkcs7Decryptor) Decrypt(key bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	return AESCBCPKCS7Decrypt(key.(*aesPrivateKey).privateKey, ciphertext)
}

// AESCBCPKCS7Encrypt 利用给定的密钥对明文进行 AES 加密。
func AESCBCPKCS7Encrypt(key, plaintext []byte) ([]byte, error) {
	plaintext = pkcs7Padding(plaintext)
	return aesCBCEncrypt(key, plaintext)
}

// AESCBCPKCS7EncryptWithRand 利用给定的伪随机数产生器、密钥和明文，对明文进行 AES 加密，伪随机数产生器用于产生初始向量 IV。
func AESCBCPKCS7EncryptWithRand(prng io.Reader, key, plaintext []byte) ([]byte, error) {
	plaintext = pkcs7Padding(plaintext)
	return aesCBCEncryptWithRand(prng, key, plaintext)
}

// AESCBCPKCS7EncryptWithIV 利用给定的初始向量、密钥和明文，对明文进行 AES 加密。
func AESCBCPKCS7EncryptWithIV(iv []byte, key, plaintext []byte) ([]byte, error) {
	plaintext = pkcs7Padding(plaintext)
	return aesCBCEncryptWithIV(iv, key, plaintext)
}

// AESCBCPKCS7Decrypt 利用给定的密钥和密文，对密文进行解密。
func AESCBCPKCS7Decrypt(key, ciphertext []byte) ([]byte, error) {
	plaintext, err := aesCBCDecrypt(key, ciphertext)
	if err != nil {
		return nil, err
	}
	return pkcs7UnPadding(plaintext)
}

// GetRandomBytes 随机获取 size 个数的字节。
func GetRandomBytes(size int) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("size must be larger than 0, however, the given size is [%d]", size)
	}

	buffer := make([]byte, size)

	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != size {
		return nil, fmt.Errorf("want to get [%d] random bytes, but got [%d] random bytes", size, n)
	}

	return buffer, nil
}

// pkcs7Padding 补齐字节切片长度。比如给定的字节切片 src 的长度是 26，那么根据填充规则：16-26%16=6，需要在 src 的后面追加 6 个 byte(6)。
func pkcs7Padding(src []byte) []byte {
	padding := 16 - len(src)%16                             // 计算要填充的字节数
	padtext := bytes.Repeat([]byte{byte(padding)}, padding) // 计算要填充的内容
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	padding := src[length-1] // 计算填充的元素

	if padding > 16 || padding == 0 {
		return nil, fmt.Errorf("invalid pkcs7 padding element [%d], it should be > 0 && < 16", padding)
	}

	origin := src[:length-int(padding)]
	for i, b := range src[length-int(padding):] {
		if b != padding {
			return nil, fmt.Errorf("invalid pkcs7 padding element, because src[%d]=%d, and padding=%d", i, b, padding)
		}
	}

	return origin, nil
}

// aesCBCEncrypt 函数实际上是在调用 aesCBCEncryptWithRand(rand.Reader, key, plaintext) 函数。
func aesCBCEncrypt(key, plaintext []byte) ([]byte, error) {
	return aesCBCEncryptWithRand(rand.Reader, key, plaintext)
}

// aesCBCEncryptWithRand 通过给定一个伪随机序列生成器生成随机初始向量，然后利用 AES 算法对明文进行加密。
func aesCBCEncryptWithRand(prng io.Reader, key, plaintext []byte) ([]byte, error) {
	if len(plaintext)%16 != 0 {
		return nil, fmt.Errorf("invalid plaintext, it's length must be multiple of 16, however, it's length is actually [%d]", len(plaintext))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, 16+len(plaintext))
	iv := ciphertext[:16]                            // 初始向量设为 [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
	if _, err := io.ReadFull(prng, iv); err != nil { // 随机化初始向量
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[16:], plaintext)

	return ciphertext, nil
}

// aesCBCEncryptWithIV 通过给定的初始向量，然后利用 AES 算法对明文进行加密。
func aesCBCEncryptWithIV(iv, key, plaintext []byte) ([]byte, error) {
	if len(plaintext)%16 != 0 {
		return nil, fmt.Errorf("invalid plaintext, it's length must be multiple of 16, however, it's length is actually [%d]", len(plaintext))
	}

	if len(iv) != 16 {
		return nil, fmt.Errorf("invalid initial vector, it's length must be 16, however, it's length is actually [%d]", len(iv))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, 16+len(plaintext))
	copy(ciphertext[:16], iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[16:], plaintext)

	return ciphertext, nil
}

// aesCBCDecrypt 根据提供的密钥解密密文。
func aesCBCDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%16 != 0 {
		return nil, fmt.Errorf("invalid ciphertext, it's length must be multiple of 16, but actually it is [%d]", len(ciphertext))
	}
	iv := ciphertext[:16]
	ciphertext = ciphertext[16:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}

/*** 🐋 ***/

type aesPrivateKey struct {
	privateKey []byte
	exportable bool
}

func (key *aesPrivateKey) Bytes() ([]byte, error) {
	if key.exportable {
		return key.privateKey, nil
	}
	return nil, errors.New("this aes key is unexportable")
}

// SKI 返回 AES 私钥的 sha256 哈希值。
func (key *aesPrivateKey) SKI() []byte {
	hash := sha256.New()
	hash.Write([]byte{0x01})
	hash.Write(key.privateKey)
	return hash.Sum(nil)
}

func (key *aesPrivateKey) Symmetric() bool {
	return true
}

func (key *aesPrivateKey) IsPrivate() bool {
	return true
}

func (key *aesPrivateKey) PublicKey() (bccsp.Key, error) {
	return nil, errors.New("aes key doesn't have public key")
}
