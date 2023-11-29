package msp

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/11090815/hyperchain/bccsp"
	"github.com/11090815/hyperchain/common/hlogging"
	pbmsp "github.com/11090815/hyperchain/protos-go/msp"
	"github.com/11090815/hyperchain/vars"
	"google.golang.org/protobuf/proto"
)

var mspIdentityLogger = hlogging.MustGetLogger("msp.identity")

type IdentityIdentifier struct {
	// 成员服务提供商的身份标识符。
	Mspid string

	// x509.Certificate.Raw 的哈希值，并对哈希值计算 16 进制，得到的字符串。
	Id string
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type identity struct {
	id *IdentityIdentifier

	cert *x509.Certificate

	publicKey bccsp.Key

	msp *bccspmsp

	validationMutex sync.Mutex

	validated bool

	validationErr error
}

func newIdentity(cert *x509.Certificate, pk bccsp.Key, msp *bccspmsp) (Identity, error) {
	mspIdentityLogger.Debugf("Creating identity instance for certificate [%d].", cert.SerialNumber)

	cert, _ = msp.santizeCert(cert)

	hashOpt, err := bccsp.GetHashOpt(msp.cryptoConfig.HashAlgorithm)
	if err != nil {
		return nil, vars.ErrorGettingHashOption{Reason: err.Error()}
	}

	digest, err := msp.csp.Hash(cert.Raw, hashOpt)
	if err != nil {
		return nil, fmt.Errorf("failed hashing raw certificate to compute the id of the IdentityIdentifier: [%s]", err.Error())
	}

	id := &IdentityIdentifier{
		Mspid: msp.name,
		Id:    hex.EncodeToString(digest),
	}

	return &identity{id: id, cert: cert, publicKey: pk, msp: msp}, nil
}

// ExpiresAt 返回证书的过期时间。
func (id *identity) ExpiresAt() time.Time {
	return id.cert.NotAfter
}

func (id *identity) SatisfiesPrincipal(principal *pbmsp.MSPPrincipal) error {
	return id.msp.SatisfiesPrincipal(id, principal)
}

func (id *identity) GetIdentifier() *IdentityIdentifier {
	return id.id
}

func (id *identity) GetMSPIdentifier() string {
	return id.id.Mspid
}

// Validate 验证该身份指向的 x509 证书是否被撤销，如果被撤销，则验证失败，否则按照 msp 内部定义的验证规则继续验证。
func (id *identity) Validate() error {
	return id.msp.Validate(id)
}

func (id *identity) GetOrganizationalUnits() []*OUIdentifier {
	if id.cert == nil {
		return nil
	}

	ccid, err := id.msp.getCertificateChainIdentifier(id)
	if err != nil {
		mspIdentityLogger.Errorf("failed getting certificate ")
		return nil
	}

	var ous []*OUIdentifier
	for _, unit := range id.cert.Subject.OrganizationalUnit {
		ous = append(ous, &OUIdentifier{
			OrganizationalUnitIdentifier: unit,
			CertifiersIdentifier:         ccid,
		})
	}

	return ous
}

func (id *identity) Anonymous() bool {
	return false
}

func (id *identity) Serialize() ([]byte, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.cert.Raw})
	if certPEM == nil {
		return nil, errors.New("failed convert ASN.1 DER format certificate to PEM")
	}

	sid := &pbmsp.SerializedIdentity{Mspid: id.id.Mspid, IdBytes: certPEM}
	serializedId, err := proto.Marshal(sid)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling SerializedIdentity for identity: [%s]", err.Error())
	}

	return serializedId, nil
}

func (id *identity) Verify(msg, sig []byte) error {
	hashOpt, err := bccsp.GetHashOpt(id.msp.cryptoConfig.HashAlgorithm)
	if err != nil {
		return vars.ErrorGettingHashOption{Reason: err.Error()}
	}

	digest, err := id.msp.csp.Hash(msg, hashOpt)
	if err != nil {
		return fmt.Errorf("failed computing digest for message: [%s]", err.Error())
	}

	mspIdentityLogger.Debugf("Verify signature: signer identity (certificate subject=%s issuer=%s serial-number=%d)", id.cert.Subject, id.cert.Issuer, id.cert.SerialNumber)

	valid, err := id.msp.csp.Verify(id.publicKey, sig, digest, nil)
	if err != nil {
		return fmt.Errorf("could not determine whether the signature is valid or not: [%s]", err.Error())
	} else if !valid {
		mspIdentityLogger.Errorf("The signature is invalid for signer identity (certificate subject=%s issuer=%s serial-number=%d)", id.cert.Subject, id.cert.Issuer, id.cert.SerialNumber)
		return errors.New("the signature is invalid")
	}

	return nil
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type signingIdentity struct {
	identity

	signer crypto.Signer
}

func newSigningIdentity(cert *x509.Certificate, pk bccsp.Key, signer crypto.Signer, msp *bccspmsp) (SigningIdentity, error) {
	id, err := newIdentity(cert, pk, msp)
	if err != nil {
		return nil, err
	}

	return &signingIdentity{
		identity: identity{
			id:        id.(*identity).id,
			cert:      id.(*identity).cert,
			publicKey: id.(*identity).publicKey,
			msp:       id.(*identity).msp,
		},
		signer: signer,
	}, nil
}

func (id *signingIdentity) Sign(msg []byte) ([]byte, error) {
	hashOpt, err := bccsp.GetHashOpt(id.msp.cryptoConfig.HashAlgorithm)
	if err != nil {
		return nil, vars.ErrorGettingHashOption{Reason: err.Error()}
	}

	digest, err := id.msp.csp.Hash(msg, hashOpt)
	if err != nil {
		return nil, err
	}

	return id.signer.Sign(rand.Reader, digest, nil)
}

func (id *signingIdentity) GetPublicVersion() Identity {
	return &id.identity
}
