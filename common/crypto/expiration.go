package crypto

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/11090815/hyperchain/protos-go/msp"
	"google.golang.org/protobuf/proto"
)

// ExpiresAt 给定一个 &msp.SerializedIdentity{} 的序列化数据，返回其中节点身份证书的过期时间。
func ExpiresAt(identityBytes []byte) time.Time {
	sID := &pbmsp.SerializedIdentity{}
	if err := proto.Unmarshal(identityBytes, sID); err != nil {
		return time.Time{}
	}
	return certExpirationTime(sID.IdBytes)
}

// TrackExpiration 传入的第二个参数 serverCert 是 x509 身份证书的 ASN.1 DER PEM 格式的数据。传入的第三个参数 clientCertChain 是一连串的客户端的 x509 身份证书
// 的 ASN.1 DER PEM 格式的数据。
func TrackExpiration(tls bool, serverCrt []byte, clientCertChain [][]byte, sIDBytes []byte, info MessageFunc, warn MessageFunc, now time.Time, s Scheduler) {
	sID := &pbmsp.SerializedIdentity{}
	if err := proto.Unmarshal(sIDBytes, sID); err != nil {
		return
	}

	trackCertExpiration(sID.IdBytes, "enrollment", info, warn, now, s)

	if !tls {
		return
	}

	trackCertExpiration(serverCrt, "server TLS", info, warn, now, s)

	if len(clientCertChain) == 0 || len(clientCertChain[0]) == 0 {
		return
	}

	trackCertExpiration(clientCertChain[0], "client TLS", info, warn, now, s)
}

type MessageFunc func(format string, args ...interface{})

type Scheduler func(d time.Duration, f func()) *time.Timer

// trackCertExpiration 跟踪证书的过期时间，在证书还有一个星期就过期的时候，会通过日志发出一个证书即将在一周内过期的警告。
func trackCertExpiration(raw []byte, role string, info MessageFunc, warn MessageFunc, now time.Time, sched Scheduler) {
	expirationTime := certExpirationTime(raw)
	if expirationTime.IsZero() {
		// 给的证书数据有问题
		return
	}

	timeLeftUntilExpiration := expirationTime.Sub(now) // 距离证书过期还剩下的时间
	if timeLeftUntilExpiration < 0 {
		warn("The certificate of %s has expired", role)
	}

	info("The certificate of %s will expire on %s", role, expirationTime)

	if timeLeftUntilExpiration < time.Hour*24*7 {
		warn("The certificate of %s will expire within one week", role)
		return
	}

	timeLeftUntilOneWeekBeforeExpiration := timeLeftUntilExpiration - time.Hour*24*7
	sched(timeLeftUntilOneWeekBeforeExpiration, func() {
		warn("The certificate of %s will expire within one week", role)
	})
}

// certExpirationTime 给定某个证书的 ASN.1 DER PEM 格式数据，对其进行解析，返回该证书的过期时间。
func certExpirationTime(pemBytes []byte) time.Time {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return time.Time{}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
		return time.Time{}
	}

	return cert.NotAfter
}

// LoNonPublicKeyMismatchErr 在日志中记载两个证书中公钥不匹配的错误（非 ErrPublicKeyMismatch 错误）。
func LoNonPublicKeyMismatchErr(log func(template string, args ...interface{}), err error, certDER1, certDER2 []byte) {
	cert1PEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER1})
	cert2PEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER2})
	log("Failed determining if public key of %s matches public key of %s: %s", cert1PEM, cert2PEM, err.Error())
}

var ErrPublicKeyMismatch = errors.New("public keys do not match")

// CertificateWithSamePublicKey 给定两个 ASN.1 DER 格式的证书数据，然后判断这两个证书中的公钥是否相同，不相同的话则会返回一个 non-nil 错误。
func CertificateWithSamePublicKey(der1, der2 []byte) error {
	pk1, err := publicKeyFromCertificate(der1)
	if err != nil {
		return err
	}

	pk2, err := publicKeyFromCertificate(der2)
	if err != nil {
		return err
	}

	if !bytes.Equal(pk1, pk2) {
		return ErrPublicKeyMismatch
	}
	return nil
}

// publicKeyFromCertificate 给定 ASN.1 DER 格式的证书数据，将其解析成 *x509.Certificate，然后提取其中的公钥，
// 将其编码成 ASN.1 DER 格式的数据，并返回。
func publicKeyFromCertificate(der []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return x509.MarshalPKIXPublicKey(cert.PublicKey)
}
