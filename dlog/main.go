package main

import (
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/ec"
)

/*
	- "github.com/xlab-si/emmy/crypto/ec"
		Is a wrapper for the elliptic curve library (crypto/ecdsa)
		Wraps elliptic curve group functions as well.

	- "github.com/xlab-si/emmy/crypto/common"
		Is a library for a lot of common cryptographic functions,
		however we only use the GetRandomInt function with the gr
*/

func NewProver(curve ec.Curve) *Prover {
	return &Prover{
		Group: ec.NewGroup(curve),
	}
}

func NewVerifier(curve ec.Curve) *Verifier {
	return &Verifier{
		Group: ec.NewGroup(curve),
	}
}

//This is essentially step 1 in the Schnorr protocol.
// P chooses r at random in Z_q and sends (a = g^r mod p) to the verifier
func (p *Prover) GenerateProofData(generator *ec.GroupElement) {
	secret := common.GetRandomInt(p.Group.Q) //random secret from Z_q
	p.generator = generator
	p.secret = secret
}

func (p *Prover) MakeCommitment() {
	r := common.GetRandomInt(p.Group.Q) // random
	p.r = r
}

// Perhaps not an obvious name for the method?..
// A part of step 1 in the three-way-protocol.
func (p *Prover) PublishProof() *ec.GroupElement {
	return p.Group.Exp(p.generator, p.r) // u = g^r
}

// It receives challenge defined by a verifier, and returns z = r + challenge * w. >>>>>NOT MY COMMENT<<<<<
func (p *Prover) GetProofData(challenge *big.Int) *big.Int {
	// z = r + challenge * secret >>>>>NOT MY COMMENT<<<<<
	z := new(big.Int)
	z.Mul(challenge, p.secret) // z = c * x
	z.Add(z, p.r)              // z = z + r
	z.Mod(z, p.Group.Q)        // z mod group-generator
	return z                   // z = r + c*x
}

func (v *Verifier) SetProofRandomData(x, subgrp, y *ec.GroupElement) {
	v.x = x
	v.generator = subgrp
	v.y = y
}

func (v *Verifier) GenerateChallenge() *big.Int {
	challenge := common.GetRandomInt(v.Group.Q)
	v.challenge = challenge
	return challenge
}

func (v *Verifier) Verify(z *big.Int) bool {
	left := v.Group.Exp(v.generator, z) //g^z
	r := v.Group.Exp(v.y, v.challenge)  //h^c
	right := v.Group.Mul(r, v.x)        //u*h^c
	isOk := left.Equals(right)
	return isOk
}

func main() {
	curve := ec.P256
	group := ec.NewGroup(curve)    // Init group from curve
	prover := NewProver(curve)     // Agents: prover
	verifier := NewVerifier(curve) // Agents: verifier

	r := common.GetRandomInt(group.Q)
	g := group.ExpBaseG(r) // Some element of order q in Z_p*
	prover.MakeCommitment()
	prover.GenerateProofData(g)      // Prover generates random secret
	h := group.Exp(g, prover.secret) //h = g^x

	u := prover.PublishProof() //

	verifier.SetProofRandomData(u, g, h)

	challenge := verifier.GenerateChallenge()

	z := prover.GetProofData(challenge)

	verified := verifier.Verify(z)
	fmt.Println("Proof is correct: ", verified)
}
