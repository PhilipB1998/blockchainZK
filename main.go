package main

import (
	"fmt"
	. "swag/zk"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/ec"
)

// type Verifier struct {
// 	Group     *ec.Group
// 	h         *ec.GroupElement
// 	generator *ec.GroupElement
// 	u         *ec.GroupElement
// 	challenge *big.Int
// }

// type Prover struct {
// 	Group     *ec.Group
// 	generator *ec.GroupElement
// 	x         *big.Int
// 	r         *big.Int // ProofRandomData
// }

// /*
// 	- "github.com/xlab-si/emmy/crypto/ec"
// 		Is a wrapper for the elliptic curve library (crypto/ecdsa)
// 		Wraps elliptic curve group functions as well.

// 	- "github.com/xlab-si/emmy/crypto/common"
// 		Is a library for a lot of common cryptographic functions,
// 		however we only use the GetRandomInt function with the gr
// */

// func NewProver(curve ec.Curve) *Prover {
// 	return &Prover{
// 		Group: ec.NewGroup(curve),
// 	}
// }

// func NewVerifier(curve ec.Curve) *Verifier {
// 	return &Verifier{
// 		Group: ec.NewGroup(curve),
// 	}
// }

// // P chooses r at random in Z_q and sends (a = g^r mod p) to the verifier
// func (p *Prover) GenerateProofData(generator *ec.GroupElement) {
// 	x := common.GetRandomInt(p.Group.Q) //random x from Z_q
// 	p.generator = generator
// 	p.x = x
// }

// func (p *Prover) GenerateH(generator *ec.GroupElement, group *ec.Group) *ec.GroupElement {

// 	random := common.GetRandomInt(p.Group.Q)
// 	p.r = random

// 	p.GenerateProofData(generator) // Prover generates random x
// 	h := group.Exp(generator, p.x) //h = g^x
// 	return h
// }

// // Perhaps not an obvious name for the method?..
// // A part of step 1 in the three-way-protocol.
// func (p *Prover) GenerateU() *ec.GroupElement {
// 	return p.Group.Exp(p.generator, p.r) // u = g^r
// }

// // It receives challenge defined by a verifier, and returns z = r + challenge * w. >>>>>NOT MY COMMENT<<<<<
// func (p *Prover) GetProofData(challenge *big.Int) *big.Int {
// 	// z = r + challenge * x >>>>>NOT MY COMMENT<<<<<
// 	z := new(big.Int)
// 	z.Mul(challenge, p.x) // z = c * x
// 	z.Add(z, p.r)         // z = z + r
// 	z.Mod(z, p.Group.Q)   // z mod group-order
// 	return z              // z = r + c*x
// }

// func (v *Verifier) SetH(h *ec.GroupElement) {
// 	v.h = h
// }

// func (v *Verifier) SetU(u *ec.GroupElement) {
// 	v.u = u
// }

// func (v *Verifier) SetGenerator(generator *ec.GroupElement) {
// 	v.generator = generator
// }

// func (v *Verifier) GenerateChallenge() *big.Int {
// 	challenge := common.GetRandomInt(v.Group.Q)
// 	v.challenge = challenge
// 	return challenge
// }

// func (v *Verifier) Verify(z *big.Int) bool {
// 	left := v.Group.Exp(v.generator, z) //g^z
// 	r := v.Group.Exp(v.h, v.challenge)  //h^c
// 	right := v.Group.Mul(r, v.u)        //u * h^c
// 	isOk := left.Equals(right)
// 	return isOk
// }

func main() {
	curve := ec.P256
	group := ec.NewGroup(curve)    // Init group from curve
	prover := NewProver(curve)     // Agents: prover
	verifier := NewVerifier(curve) // Agents: verifier

	r := common.GetRandomInt(group.Q)
	generator := group.ExpBaseG(r) //generator g for group

	verifier.SetGenerator(generator)
	prover.GenerateProofData(generator) // Prover generates random x

	h := prover.GenerateH(generator, group)   //Prover calculates h = g^x
	verifier.SetH(h)                          //Verifier gets h
	u := prover.GenerateU()                   //Prover calculates u = g^r
	verifier.SetU(u)                          //Verifier gets u
	challenge := verifier.GenerateChallenge() //Verifier generates a challenge

	z := prover.GetProofData(challenge) //Prover calculates z = r + cx

	verified := verifier.Verify(z) //Verifier verifies g^z = u * h^c
	fmt.Println("Verifier verifies that prover knows of x.")
	fmt.Println("Prover knows of x: ", verified)
}
