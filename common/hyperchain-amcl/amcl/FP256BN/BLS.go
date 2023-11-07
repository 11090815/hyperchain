package fp256bn

import "github.com/11090815/hyperchain/common/hyperchain-amcl/amcl"



const BFS int = int(MODBYTES)
const BGS int = int(MODBYTES)
const BLS_OK int = 0
const BLS_FAIL int = -1

/* hash a message to an ECP point, using SHA3 */

func Bls_hash(m string) *ECP {
	sh := amcl.NewSHA3(amcl.SHA3_SHAKE256)
	var hm [BFS]byte
	t := []byte(m)
	for i := 0; i < len(t); i++ {
		sh.Process(t[i])
	}
	sh.Shake(hm[:], BFS)
	P := ECP_mapit(hm[:])
	return P
}

/* generate key pair, private key S, public key W */

func KeyPairGenerate(rng *amcl.RAND, S []byte, W []byte) int {
	G := ECP2_generator()
	q := NewBIGints(CURVE_Order)
	s := Randomnum(q, rng)
	s.ToBytes(S)
	G = G2mul(G, s)
	G.ToBytes(W)
	return BLS_OK
}

/* Sign message m using private key S to produce signature SIG */

func Sign(SIG []byte, m string, S []byte) int {
	D := Bls_hash(m)
	s := FromBytes(S)
	D = G1mul(D, s)
	D.ToBytes(SIG, true)
	return BLS_OK
}

/* Verify signature given message m, the signature SIG, and the public key W */

func Verify(SIG []byte, m string, W []byte) int {
	HM := Bls_hash(m)
	D := ECP_fromBytes(SIG)
	G := ECP2_generator()
	PK := ECP2_fromBytes(W)
	D.neg()

	// Use new multi-pairing mechanism
	r := initmp()
	another(r, G, D)
	another(r, PK, HM)
	v := miller(r)

	//.. or alternatively
	//	v := Ate2(G, D, PK, HM)

	v = Fexp(v)
	if v.Isunity() {
		return BLS_OK
	} else {
		return BLS_FAIL
	}
}
