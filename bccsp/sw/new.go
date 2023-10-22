package sw

import (
	"crypto/sha256"
	"reflect"

	"github.com/11090815/hyperchain/bccsp"
)

func NewBCCSP(ks bccsp.KeyStore) (bccsp.BCCSP, error) {
	csp, err := NewCSP(ks)
	if err != nil {
		return nil, err
	}

	// 设置加密器 Encrypter。
	csp.AddWrapper(reflect.TypeOf(&aesKey{}), &aescbcpkcs7Encryptor{})

	// 设置解密器 Decrypter。
	csp.AddWrapper(reflect.TypeOf(&aesKey{}), &aescbcpkcs7Decryptor{})

	// 设置签名器 Signer。
	csp.AddWrapper(reflect.TypeOf(&ecdsaPrivateKey{}), &ecdsaSigner{})

	// 设置签名验证器 Verifier。
	csp.AddWrapper(reflect.TypeOf(&ecdsaPrivateKey{}), &ecdsaPrivateKeyVerifier{})
	csp.AddWrapper(reflect.TypeOf(&ecdsaPublicKey{}), &ecdsaPublicKeyVerifier{})

	// 设置 Hasher。
	csp.AddWrapper(reflect.TypeOf(&bccsp.SHA256Opts{}), &hasher{hash: sha256.New})

	// 设置密钥生成器 KeyGenerator。
	csp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAKeyGenOpts{}), &ecdsaKeyGenerator{})
	csp.AddWrapper(reflect.TypeOf(&bccsp.AESKeyGenOpts{}), &aesKeyGenerator{})

	// 设置密钥衍生器 KeyDeriver。
	csp.AddWrapper(reflect.TypeOf(&ecdsaPublicKey{}), &ecdsaPublicKeyDeriver{})
	csp.AddWrapper(reflect.TypeOf(&ecdsaPrivateKey{}), &ecdsaPrivateKeyDeriver{})
	csp.AddWrapper(reflect.TypeOf(&aesKey{}), &aesKeyDeriver{})

	// 设置密钥导入器 KeyImporter。
	csp.AddWrapper(reflect.TypeOf(&bccsp.AESKeyImportOpts{}), &aesKeyImporter{})
	csp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAPKIXPublicKeyImportOpts{}), &ecdsaPKIXPublicKeyImporter{})
	csp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAPrivateKeyImportOpts{}), &ecdsaPrivateKeyImporter{})

	return csp, nil
}
