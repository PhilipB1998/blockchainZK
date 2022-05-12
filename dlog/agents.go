package main

import (
	"math/big"

	"github.com/xlab-si/emmy/crypto/ec"
)

type Coordinate struct {
	X, Y *big.Int
}

type Verifier struct {
	Group     *ec.Group
	x         *ec.GroupElement
	generator  *ec.GroupElement
	y         *ec.GroupElement
	challenge *big.Int
}

type Prover struct {
	Group    *ec.Group
	generator *ec.GroupElement
	secret   *big.Int
	r        *big.Int // ProofRandomData
}
