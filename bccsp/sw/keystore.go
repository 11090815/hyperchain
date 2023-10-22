package sw

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/common/hlogging"
)

type fileBasedKeyStore struct {
	path     string
	readOnly bool
	isOpen   bool
	logger   *hlogging.HyperchainLogger
	mutex    sync.Mutex
}

func NewFileBasedKeyStore(path string, readOnly bool) (bccsp.KeyStore, error) {
	ks := &fileBasedKeyStore{
		logger: hlogging.MustGetLogger("bccsp_ks"),
	}
	return ks, ks.Init(path, readOnly)
}

func (ks *fileBasedKeyStore) Init(path string, readOnly bool) error {
	if len(path) == 0 {
		return errors.New("you should provide a non-nil path to create a key store")
	}

	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	if ks.isOpen {
		return errors.New("key store is already initialized")
	}

	ks.path = path
	ks.readOnly = readOnly

	exists, err := dirExists(path)
	if err != nil {
		return err
	}
	if !exists {
		if err = ks.createKeyStore(); err != nil {
			return err
		}
		ks.openKeyStore()
	}

	empty, err := dirEmpty(path)
	if err != nil {
		return err
	}
	if !empty {
		if err = ks.createKeyStore(); err != nil {
			return err
		}
	}

	ks.openKeyStore()
	return nil
}

func (ks *fileBasedKeyStore) ReadOnly() bool {
	return ks.readOnly
}

// GetKey 如果目录里同时存在 ecdsa 的公钥私钥对，即 sk 是 pk 对应的私钥，那么 sk 与 pk 的 ski 是一样的，在此情况下，根据 ski 获取 key，默认情况下获取到的是 ecdsa 的私钥。
func (ks *fileBasedKeyStore) GetKey(ski []byte) (key bccsp.Key, err error) {
	if len(ski) == 0 {
		return nil, errors.New("if you want to get a key, you should provide a non-nil ski")
	}

	alias := hex.EncodeToString(ski)

	suffix := ks.getSuffix(alias)

	switch suffix {
	case "aes_key":
		aesK, err := ks.loadKey(alias)
		if err != nil {
			return nil, err
		}
		return &aesKey{key: aesK, exportable: false}, nil
	case "public_key":
		pk, err := ks.loadPublicKey(alias)
		if err != nil {
			return nil, err
		}
		return &ecdsaPublicKey{publicKey: pk.(*ecdsa.PublicKey)}, nil
	case "private_key":
		sk, err := ks.loadPrivateKey(alias)
		if err != nil {
			return nil, err
		}
		return &ecdsaPrivateKey{privateKey: sk.(*ecdsa.PrivateKey)}, nil
	default:
		return nil, fmt.Errorf("cannot find the key [%s]", alias)
	}
}

func (ks *fileBasedKeyStore) StoreKey(key bccsp.Key) (err error) {
	if ks.readOnly {
		return errors.New("the key store is readonly!!!")
	}

	if key == nil {
		return errors.New("invalid key: [the content is nil]")
	}

	switch k := key.(type) {
	case *ecdsaPrivateKey:
		if err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), k.privateKey); err != nil {
			return err
		}
	case *ecdsaPublicKey:
		if err = ks.storePublicKey(hex.EncodeToString(k.SKI()), k.publicKey); err != nil {
			return err
		}
	case *aesKey:
		if err = ks.storeKey(hex.EncodeToString(k.SKI()), k.key); err != nil {
			return err
		}
	default:
		return fmt.Errorf("this key's type [%T] is not recognised, you can't store it", key)
	}

	return nil
}

// searchKeyForSKI 根据 ski 搜寻 ecdsa 的私钥。
func (ks *fileBasedKeyStore) searchKeyForSKI(ski []byte) (key bccsp.Key, err error) {
	files, _ := os.ReadDir(ks.path)

	for _, f := range files {
		if !strings.HasPrefix(f.Name(), hex.EncodeToString(ski)) {
			continue
		}

		if f.IsDir() {
			continue
		}

		if fileInfo, err := f.Info(); err != nil || fileInfo.Size() > (1<<16) {
			continue
		}

		raw, err := os.ReadFile(filepath.Join(ks.path, f.Name()))
		if err != nil {
			continue
		}
		k, err := pemToPrivateKey(raw)
		if err != nil {
			continue
		}

		switch k := k.(type) {
		case *ecdsa.PrivateKey:
			key = &ecdsaPrivateKey{privateKey: k}
		default:
			continue
		}

		if !bytes.Equal(key.SKI(), ski) {
			continue
		}

		return key, nil
	}

	return nil, fmt.Errorf("key with ski [%x] not found in %s", ski, ks.path)
}

// getSuffix 获取别名为 alias 的对象的密钥类型：[ public_key | private_key | aes_key ]。
func (ks *fileBasedKeyStore) getSuffix(alias string) string {
	// 打开 ks.path 目录，获取该目录中的所有文件。
	files, _ := os.ReadDir(ks.path)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), alias) {
			if strings.HasSuffix(f.Name(), "private_key") {
				return "private_key"
			}
			if strings.HasSuffix(f.Name(), "public_key") {
				return "public_key"
			}
			if strings.HasSuffix(f.Name(), "aes_key") {
				return "aes_key"
			}
			break
		}
	}
	return ""
}

// storePrivateKey 存储 ecdsa 私钥。
func (ks *fileBasedKeyStore) storePrivateKey(alias string, privateKey interface{}) error {
	raw, err := privateKeyToPEM(privateKey)
	if err != nil {
		ks.logger.Errorf("Failed converting private key [%s] to pem: [%s]", alias, err.Error())
		return err
	}

	path := ks.getPathForAlias(alias, "private_key")
	if err = os.WriteFile(path, raw, os.FileMode(0600)); err != nil {
		ks.logger.Errorf("Failed storing private key [%s]: [%s]", alias, err.Error())
		return err
	}
	ks.logger.Debugf("Store private key [%s] at [%s]...done", alias, ks.path)

	return nil
}

// storePublicKey 存储 ecdsa 公钥。
func (ks *fileBasedKeyStore) storePublicKey(alias string, publicKey interface{}) error {
	raw, err := publicKeyToPEM(publicKey)
	if err != nil {
		ks.logger.Errorf("Failed converting public key [%s] to pem: [%s]", alias, err.Error())
		return err
	}

	path := ks.getPathForAlias(alias, "public_key")
	if err = os.WriteFile(path, raw, os.FileMode(0600)); err != nil {
		ks.logger.Errorf("Failed storing public key [%s]: [%s]", alias, err.Error())
		return err
	}
	ks.logger.Debugf("Store public key [%s] at [%s]...done", alias, ks.path)

	return nil
}

// storeKey 存储 aes 密钥。
func (ks *fileBasedKeyStore) storeKey(alias string, key []byte) error {
	path := ks.getPathForAlias(alias, "aes_key")
	pem := aesToPEM(key)

	err := os.WriteFile(path, pem, os.FileMode(0600))
	if err != nil {
		ks.logger.Errorf("Failed storing key [%s]: [%s]", alias, err.Error())
		return err
	}
	ks.logger.Debugf("Store aes key [%s] at [%s]...done", alias, ks.path)

	return nil
}

// loadPrivateKey 加载 ecdsa 私钥。
func (ks *fileBasedKeyStore) loadPrivateKey(alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, "private_key")

	raw, err := os.ReadFile(path)
	if err != nil {
		ks.logger.Errorf("Failed loading key [%s]: [%s]", alias, err.Error())
		return nil, err
	}

	privateKey, err := pemToPrivateKey(raw)
	if err != nil {
		ks.logger.Errorf("Failed parsing private key [%s]: [%s]", alias, err.Error())
		return nil, err
	}
	ks.logger.Debugf("Loading private key [%s] at [%s]...done", alias, path)

	return privateKey, nil
}

// loadPublicKey 加载 ecdsa 公钥。
func (ks *fileBasedKeyStore) loadPublicKey(alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, "public_key")

	raw, err := os.ReadFile(path)
	if err != nil {
		ks.logger.Errorf("Failed loading key [%s]: [%s]", alias, err.Error())
		return nil, err
	}

	publicKey, err := pemToPublicKey(raw)
	if err != nil {
		ks.logger.Errorf("Failed parsing public key [%s]: [%s]", alias, err.Error())
		return nil, err
	}
	ks.logger.Debugf("Loading public key [%s] at [%s]...done", alias, path)

	return publicKey, nil
}

// loadKey 加载 aes 密钥。
func (ks *fileBasedKeyStore) loadKey(alias string) ([]byte, error) {
	path := ks.getPathForAlias(alias, "aes_key")

	pem, err := os.ReadFile(path)
	if err != nil {
		ks.logger.Errorf("Failed loading key [%s]: [%s]", alias, err.Error())
		return nil, err
	}

	key, err := pemToAES(pem)
	if err != nil {
		ks.logger.Errorf("Failed parsing key [%s]: [%s]", alias, err.Error())
		return nil, err
	}
	ks.logger.Debugf("Loading aes key [%s] at [%s]...done", alias, path)

	return key, nil
}

func (ks *fileBasedKeyStore) createKeyStore() error {
	ks.logger.Debugf("Creating file based key store at [%s].", ks.path)

	return os.MkdirAll(ks.path, os.FileMode(0755)) // -rwxr-xr-x
}

func (ks *fileBasedKeyStore) openKeyStore() {
	if ks.isOpen {
		return
	}
	ks.isOpen = true
	ks.logger.Debugf("Create file based key store at [%s]...done.", ks.path)
}

// getPathForAlias ks.path/alias_suffix
func (ks *fileBasedKeyStore) getPathForAlias(alias, suffix string) string {
	return filepath.Join(ks.path, alias+"_"+suffix)
}

// dirExists 判断给定的路径是否存在。
func dirExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// dirEmpty 判断指定的文件夹是否是空的。
func dirEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdir(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}
