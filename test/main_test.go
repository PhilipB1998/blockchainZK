package test

import (
	"crypto"
	. "swag/zk"
	"testing"
	_ "crypto/sha256"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/ec"
)

func BenchmarkTest(b *testing.B) {

	for n := 0; n < b.N; n++ {
		curve := ec.P256
		group := ec.NewGroup(curve)    // Init group from curve
		prover := NewProver(curve)     // Agents: prover
		verifier := NewVerifier(curve) // Agents: verifier

		r := common.GetRandomInt(group.Q)
		generator := group.ExpBaseG(r) //generator g for group

		verifier.SetGenerator(generator)
		prover.GenerateProofData(generator) // Prover generates random x

		h := prover.GenerateH(generator)   //Prover calculates h = g^x
		verifier.SetH(h)                          //Verifier gets h
		u := prover.GenerateU()                   //Prover calculates u = g^r
		verifier.SetU(u)                          //Verifier gets u
		challenge := verifier.GenerateChallenge() //Verifier generates a challenge

		z := prover.GetProofData(challenge) //Prover calculates z = r + cx

		verifier.Verify(z) //Verifier verifies g^z = u * h^c
	}
}

func BenchmarkTestNIZK(b *testing.B) {

	for n := 0; n < b.N; n++ {
		curve := ec.P256                            // Define curve
		group := ec.NewGroup(curve)                 // Init group from curve
		rand_secret := common.GetRandomInt(group.Q) // generate random r
		hash := crypto.SHA256
		proof := MakeProof(hash, rand_secret)
	
		proof.VerifyProof()
	}
}