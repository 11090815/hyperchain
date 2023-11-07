package fp256bn

// Modulus types
const NOT_SPECIAL int = 0
const PSEUDO_MERSENNE int = 1
const MONTGOMERY_FRIENDLY int = 2
const GENERALISED_MERSENNE int = 3

const NEGATOWER int = 0
const POSITOWER int = 1

// Modulus details
const MODBITS uint = 256        /* Number of bits in Modulus */
const PM1D2 uint = 1            /* Modulus mod 8 */
const RIADZ int = 1             /* hash-to-point Z */
const RIADZG2A int = 1          /* G2 hash-to-point Z */
const RIADZG2B int = 0          /* G2 hash-to-point Z */
const MODTYPE int = NOT_SPECIAL //NOT_SPECIAL
const QNRI int = 0              // Fp2 QNR
const TOWER int = NEGATOWER     // Tower type
const FEXCESS int32 = ((int32(1) << 24) - 1)

// Modulus Masks
const OMASK Chunk = ((Chunk(-1)) << (MODBITS % BASEBITS))
const TBITS uint = MODBITS % BASEBITS // Number of active bits in top word
const TMASK Chunk = (Chunk(1) << TBITS) - 1

const BIG_ENDIAN_SIGN bool = false
