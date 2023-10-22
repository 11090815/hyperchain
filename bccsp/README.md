## 开发说明

### 导语 - 密钥 & 选项

**签名密钥：** `&ecdsaPrivateKey{}`
```go
type ecdsaPrivateKey struct {
    privateKey *ecdsa.PrivateKey
}
```

**签名验证公钥：** `&ecdsaPublicKey{}`
```go
type ecdsaPublicKey struct {
    publicKey *ecdsa.PublicKey
}
```

**加密密钥：** `&aesKey{}`
```go
type aesKey struct {
    key []byte
}
```

### 1. 签名机制

签名的生成以及验证是利用 `ECDSA` 算法实现的，目前仅支持 `P256` 椭圆曲线上的签名算法，将来也不打算支持 `P224`、`P384` 和 `P521` 曲线。

#### 1.1 签名密钥的生成

生成签名密钥需要提供选项：`&ECDSAKeyGenOpts{Temporary bool}`，该选项可以帮助程序找到对应的 `ECDSA` 密钥生成器：`&ecdsaKeyGenerator`，该密钥生成器可以生成一个密钥 `Key` (`&ecdsaPrivateKey{}`)：
```go
func (kg *ecdsaKeyGenerator) KeyGen(opts KeyGenOpts) (Key, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating ecdsa key: [%s]", err.Error())
	}
	return &ecdsaPrivateKey{privateKey: privateKey}, nil
}
```

选项 `&ECDSAKeyGenOpts{Temporary bool}` 中的 `Temporary` 用来指示生成的 `ECDSA` 密钥是否需要被保存到 `KeyStore` 中，如果 `Temporary` 的值是 `false`，则表明该密钥不是临时的，需要被持久化到 `KeyStore` 中。

注意：`&ecdsaKeyGenerator` 只生成 `P256` 椭圆曲线上的密钥。

#### 1.2 签名密钥的派生

衍生出一个新的 `ECDSA` 签名密钥需要提供两个参数：一个是原始密钥 `Key`，包括 `ECDSA` 的公私钥 `&ecdsaPublicKey{}` 和 `&ecdsaPrivateKey{}`；另一个是衍生出新密钥时提供随机因子的选项 `KeyDerivOpts`，包括 `&ECDSAKeyDerivOpts{Temporary, Expansion}`。

`ECDSA` 密钥衍生遵循的算法如下所示：
```sh
# 生成元：G
# 原始私钥：sk
# 原始公钥：pk
# 提供一个随机因子：k
# 给定 ECDSA 算法的模数：n

# 新的私钥：sk'
# 新的公钥：pk'

k = k mod (n-1)
k = k + 1
sk' = sk + k
sk' = sk' mod n
pk' = sk' * G
```

选项 `&ECDSAKeyDerivOpts{Temporary, Expansion}` 里的 `Expansion` 字段的数据类型是 `[]byte`，它其实就是上述密钥衍生算法里的随即因子 `k`。`Temporary` 字段的数据类型是 `bool`，这个字段用来表示衍生出的新密钥是否需要持久化到 `KeyStore` 中，如果 `Temporary` 的值是 `true`，则表示衍生出的新密钥是临时密钥，不需要被持久化。

#### 1.3 签名密钥的导入

导入签名密钥需要提供选项 `&KeyImportOpts{}`，包括 `&ECDSAPKIXPublicKeyImportOpts{Temporary bool}` 和 `&ECDSAPrivateKeyImportOpts{Temporary bool}`，通过选项，程序可以找到对应的密钥导入器，前者对应的密钥导入器是 `&ecdsaPKIXPublicKeyImporter{}`，它负责导入 `&ecdsaPublicKey{}`，后者对应的密钥导入器是 `&ecdsaPrivateKeyImporter{}`，它可以导入 `&ecdsaPrivateKey{}`。

选项中的 `Temporary` 字段用来指示导入的密钥是否是临时的，如果不是临时的，则导入的密钥需要持久化到 `KeyStore` 中。

#### 1.4 签名的生成与验证

##### 1.4.1 生成签名

生成签名需要签名密钥 `&ecdsaPrivateKey{}` 的支撑，提供此种类型密钥，可以帮助程序找到对应的签名生成器 `&ecdsaSigner{}`，该密钥生成器可以生成椭圆曲线签名。

##### 1.4.2 验证签名

一般情况下，验证签名需要与签名密钥对应的公钥 `&ecdsaPublicKey{}` 的支撑，但是签名密钥 `&ecdsaPrivateKey{}` 也可以验证签名的合法性。前者可以帮助程序找到签名验证器 `&ecdsaPublicKeyVerifier{}`，后者则可以帮助程序找到签名验证器 `&ecdsaPrivateKeyVerifier{}`。两种签名验证器验证签名的思路都是利用公钥去验证椭圆曲线签名的合法性。

### 2. 加密机制

加解密是基于堆成密码算法 `AES` 实现的，目前仅支持 `256` 比特长的密钥，将来也不打算支持其他长度的 `AES` 密钥。

#### 2.1 加密密钥的生成

生成加密密钥需要提供选项：`&AESKeyGenOpts{Temporary bool}`，该选项可以帮助程序找到对应的 `AES` 密钥生成器：`&aesKeyGenerator{}`，该密钥生成器可以生成一个比特位数为 `256` 的 `AES` 密钥 `Key` (`&aesKey{}`)：
```go
func (kg *aesKeyGenerator) KeyGen(opts KeyGenOpts) (Key, error) {
	key, err := GetRandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed generating aes key: [%s]", err.Error())
	}

	return &aesKey{key: key, exportable: false}, nil
}
```

选项 `&AESKeyGenOpts{Temporary bool}` 中的 `Temporary` 用来指示生成的 `AES` 密钥是否需要被保存到 `KeyStore` 中，如果 `Temporary` 的值是 `false`，则表明该密钥不是临时的，需要被持久化到 `KeyStore` 中。

#### 2.2 加密密钥的派生

衍生出一个新的 `AES` 加密密钥需要提供两个参数：一个是原始密钥 `Key`，即 `&aesKey{}`；另一个是衍生出新密钥时提供随机因子的选项 `KeyDerivOpts`，即 `&AESKeyDerivOpts{Temporary, Arg}`。

`AES` 密钥衍生的过程如下：
```sh
# 提供一个随即因子：k
# 原始密钥：sk
# 新的密钥：sk'

# 实例化一个 HMAC
mac := hmac.New(sha256.New, sk)

# 加入随机因子
mac.Write(k)

# 得到新密钥
sk' = mac.Sum(nil)
```

选项 `&AESKeyDerivOpts{Temporary, Arg}` 里的 `Arg` 字段的数据类型是 `[]byte`，它其实就是上述密钥衍生算法里的随即因子 `k`。`Temporary` 字段的数据类型是 `bool`，这个字段用来表示衍生出的新密钥是否需要持久化到 `KeyStore` 中，如果 `Temporary` 的值是 `true`，则表示衍生出的新密钥是临时密钥，不需要被持久化。

#### 2.3 加密密钥的导入

导入加密密钥需要提供选项 `&KeyImportOpts{}`，即 `&AESKeyImportOpts{Temporary bool}`，通过选项，程序可以找到对应的密钥导入器 `&aesKeyImporter{}`，它负责导入 `&aesKey{}`。

选项中的 `Temporary` 字段用来指示导入的密钥是否是临时的，如果不是临时的，则导入的密钥需要持久化到 `KeyStore` 中。

#### 2.4 密文的生成与解密

##### 2.4.1 加密

生成密文需要加密密钥 `&aesKey{}` 的支撑，提供此种类型的密钥，可以帮助程序找到对应的密文生成器 `&aescbcpkcs7Encryptor{}`，该密文生成器可以按照 `AES` 算法对明文进行加密。在生成密文时需要提供一个选项 `EncryptOpts`，即 `&AESCBCPKCS7ModeOpts{IV, PRNG}`，该选项对于生成密文具有大作用，其中的 `IV` 字段的数据类型是 `[]byte`，如果该字段不为空的话，则会将 `IV` 作为 `AES` 加密算法中的初始向量，但是，如果 `IV` 是空的话，则会利用 `PRNG` 这个伪随机数发生器来随机产生一个初始向量，`PRNG` 的数据类型是 `io.Reader`。

##### 2.4.2 解密

解密密文需要提供解密密钥 `&aesKey{}`，提供此种类型的密钥，可以帮助程序找到对应的解密器 `&aescbcpkcs7Decryptor{}`。

### 3. 密钥存储机制

`KeyStore` 接口定义了 `KeyStore` 的功能：
- `ReadOnly() bool`：反映当前的 `KeyStore` 是否支持存储新密钥的功能。
- `GetKey(ski []byte) (Key, error)`：从 `KeyStore` 中取出对应的密钥。
- `StoreKey(key Key) error`：在 `KeyStore` 中存储密钥。

结构体 `fileBasedKeyStore` 实现了 `KeyStore` 接口所定义的功能：
```go
type fileBasedKeyStore struct {
	path     string
	readOnly bool
	isOpen   bool
	logger   *hlogging.HyperchainLogger
	mutex    sync.Mutex
}
```
