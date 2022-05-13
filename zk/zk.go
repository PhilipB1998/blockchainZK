package zk

import (
	"math/big"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/ec"
)


type Verifier struct {
	Group     *ec.Group
	h         *ec.GroupElement
	generator *ec.GroupElement
	u         *ec.GroupElement
	challenge *big.Int
}

type Prover struct {
	Group     *ec.Group
	generator *ec.GroupElement
	x         *big.Int
	r         *big.Int // ProofRandomData
}


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

// P chooses r at random in Z_q and sends (a = g^r mod p) to the verifier
func (p *Prover) GenerateProofData(generator *ec.GroupElement) {
	x := common.GetRandomInt(p.Group.Q) //random x from Z_q
	p.generator = generator
	p.x = x
}

func (p *Prover) GenerateH(generator *ec.GroupElement, group *ec.Group) *ec.GroupElement {

	random := common.GetRandomInt(p.Group.Q)
	p.r = random

	p.GenerateProofData(generator) // Prover generates random x
	h := group.Exp(generator, p.x) //h = g^x
	return h
}

// Perhaps not an obvious name for the method?..
// A part of step 1 in the three-way-protocol.
func (p *Prover) GenerateU() *ec.GroupElement {
	return p.Group.Exp(p.generator, p.r) // u = g^r
}

// returns z = r + challenge * w.
// Challenge is made by the verifier. 
func (p *Prover) GetProofData(challenge *big.Int) *big.Int {
	z := new(big.Int)
	z.Mul(challenge, p.x) // z = c * x
	z.Add(z, p.r)         // z = z + r
	z.Mod(z, p.Group.Q)   // z mod group-order
	return z              // z = r + c*x mod q
}


func (v *Verifier) SetH(h *ec.GroupElement) {
	v.h = h
}

func (v *Verifier) SetU(u *ec.GroupElement) {
	v.u = u
}

func (v *Verifier) SetGenerator(generator *ec.GroupElement) {
	v.generator = generator
}

func (v *Verifier) GenerateChallenge() *big.Int {
	challenge := common.GetRandomInt(v.Group.Q)
	v.challenge = challenge
	return challenge
}

func (v *Verifier) Verify(z *big.Int) bool {
	left := v.Group.Exp(v.generator, z) //g^z
	r := v.Group.Exp(v.h, v.challenge)  //h^c
	right := v.Group.Mul(r, v.u)        //u * h^c
	isOk := left.Equals(right)
	return isOk
}