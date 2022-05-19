package main

import (
	"crypto"
	_ "crypto/sha256"
	"fmt"
	. "swag/zk"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/ec"
)

// This is the ZK version, please rename the method to main()
// if you want to test this version
func main1() {
	curve := ec.P256                  // Define curve
	group := ec.NewGroup(curve)       // Init group from curve
	prover := NewProver(curve)        // Agents: prover
	verifier := NewVerifier(curve)    // Agents: verifier
	a := common.GetRandomInt(group.Q) // generate random r
	generator := group.ExpBaseG(a)    // generator g for group
	verifier.SetGenerator(generator)
	prover.GenerateProofData(generator) // Prover generates random x and sets the generator
	h := prover.GenerateH(generator)    // Prover calculates h = g^x
	verifier.SetH(h)                    // Verifier gets h

	u := prover.GenerateU()                   // Prover calculates u = g^r
	verifier.SetU(u)                          // Verifier gets u
	challenge := verifier.GenerateChallenge() // Verifier generates a challenge

	z := prover.GetProofData(challenge) // Prover calculates z = r + cx (mod q)

	verified := verifier.Verify(z) // Verifier verifies g^z = u * h^c
	fmt.Println("Verifier verifies that prover knows of x.")
	fmt.Println("Prover knows of x: ", verified)
}

// This is the NIZK version, please rename the method to main()
// if you want to test this version
func main() {
	curve := ec.P256                            // Define curve
	group := ec.NewGroup(curve)                 // Init group from curve
	rand_secret := common.GetRandomInt(group.Q) // generate random r
	hash := crypto.SHA256
	proof := MakeProof(hash, rand_secret)

	isLegit := proof.VerifyProof()
	fmt.Println("NIZK is legit: ", isLegit)
}
