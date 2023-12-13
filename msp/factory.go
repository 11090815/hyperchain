package msp

import "github.com/11090815/hyperchain/bccsp"

func New(csp bccsp.BCCSP) MSP {
	return newBCCSPMSP(csp)
}
