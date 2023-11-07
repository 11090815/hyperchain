package fp256bn

import "github.com/11090815/hyperchain/common/hyperchain-amcl/core"



const BFS int = int(MODBYTES)
const BGS int = int(MODBYTES)
const BLS_OK int = 0
const BLS_FAIL int = -1

var G2_TAB []*FP4

func ceil(a int,b int) int {
    return (((a)-1)/(b)+1)
}

/* output u \in F_p */
func hash_to_field(hash int,hlen int ,DST []byte,M []byte,ctr int) []*FP {
	q := NewBIGints(Modulus)
	L := ceil(q.nbits()+AESKEY*8,8)
	var u []*FP
	var fd =make([]byte,L)
	OKM:=core.XMD_Expand(hash,hlen,L*ctr,DST,M)
	
	for i:=0;i<ctr;i++ {
		for j:=0;j<L;j++ {
			fd[j]=OKM[i*L+j];
		}
		u = append(u,NewFPbig(DBIG_fromBytes(fd).Mod(q)))
	}
	return u
}


/* hash a message to an ECP point, using SHA2, random oracle method */
func bls_hash_to_point(M []byte) *ECP {
	DST := []byte("BLS_SIG_FP256BNG1_XMD:SHA-256_SVDW_RO_NUL_")
	u := hash_to_field(core.MC_SHA2,HASH_TYPE,DST,M,2)

	P:=ECP_map2point(u[0])
	P1 := ECP_map2point(u[1]);
	P.Add(P1)
	P.Cfp()
	P.Affine()
	return P
}

func Init() int {
	G := ECP2_generator()
	if G.Is_infinity() {
		return BLS_FAIL
	}
	G2_TAB = precomp(G)
	return BLS_OK
}

/* generate key pair, private key S, public key W */
func KeyPairGenerate(IKM []byte, S []byte, W []byte) int {
	r := NewBIGints(CURVE_Order)
	L := ceil(3*ceil(r.nbits(),8),2)
	LEN:=core.InttoBytes(L, 2)
	AIKM:=make([]byte,len(IKM)+1) 
	for i:=0;i<len(IKM);i++ {
		AIKM[i]=IKM[i]
	}
	AIKM[len(IKM)]=0

	G := ECP2_generator()
	if G.Is_infinity() {
		return BLS_FAIL
	}
	SALT := []byte("BLS-SIG-KEYGEN-SALT-")
	PRK := core.HKDF_Extract(core.MC_SHA2,HASH_TYPE,SALT,AIKM)
	OKM := core.HKDF_Expand(core.MC_SHA2,HASH_TYPE,L,PRK,LEN)

	dx:= DBIG_fromBytes(OKM[:])
	s:= dx.Mod(r)
	s.ToBytes(S)
// SkToPk
	G = G2mul(G, s)
	G.ToBytes(W,true)
	return BLS_OK
}

/* Sign message M using private key S to produce signature SIG */

func Core_Sign(SIG []byte, M []byte, S []byte) int {
	D := bls_hash_to_point(M)
	s := FromBytes(S)
	D = G1mul(D, s)
	D.ToBytes(SIG, true)
	return BLS_OK
}

/* Verify signature given message m, the signature SIG, and the public key W */

func Core_Verify(SIG []byte, M []byte, W []byte) int {
	HM := bls_hash_to_point(M)
	
	D := ECP_fromBytes(SIG)
	if !G1member(D) {return BLS_FAIL}
	D.Neg()

	PK := ECP2_fromBytes(W)
	if !G2member(PK) {return BLS_FAIL}
	// Use new multi-pairing mechanism

	r := Initmp()
	Another_pc(r, G2_TAB, D)
	Another(r, PK, HM)
	v := Miller(r)

	//.. or alternatively
	//	G := ECP2_generator()
	//	if G.Is_infinity() {return BLS_FAIL}
	//	v := Ate2(G, D, PK, HM)

	v = Fexp(v)

	if v.Isunity() {
		return BLS_OK
	} else {
		return BLS_FAIL
	}
}
