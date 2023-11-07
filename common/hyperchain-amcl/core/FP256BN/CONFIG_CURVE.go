package fp256bn

// Curve types
const WEIERSTRASS int = 0
const EDWARDS int = 1
const MONTGOMERY int = 2

// Pairing Friendly?
const NOT int = 0
const BN int = 1
const BLS12 int = 2
const BLS24 int = 3
const BLS48 int = 4

// Pairing Twist type
const D_TYPE int = 0
const M_TYPE int = 1

// Sparsity
const FP_ZERO int = 0
const FP_ONE int = 1
const FP_SPARSEST int = 2
const FP_SPARSER int = 3
const FP_SPARSE int = 4
const FP_DENSE int = 5

// Pairing x parameter sign
const POSITIVEX int = 0
const NEGATIVEX int = 1

// Curve type

const CURVETYPE int = WEIERSTRASS
const CURVE_A int = 0
const CURVE_PAIRING_TYPE int = BN

// Pairings only

const SEXTIC_TWIST int = M_TYPE
const SIGN_OF_X int = NEGATIVEX
const ATE_BITS int = 66
const G2_TABLE int = 83
const HTC_ISO int = 0
const HTC_ISO_G2 int = 0

// associated hash function and AES key size

const HASH_TYPE int = 32
const AESKEY int = 16

const ALLOW_ALT_COMPRESS bool = false

// These are manually decided policy decisions. To block any potential patent issues set to false.

const USE_GLV bool = true
const USE_GS_G2 bool = true
const USE_GS_GT bool = true