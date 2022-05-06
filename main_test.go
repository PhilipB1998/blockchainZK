package main

import (
	"crypto/rand"
	"testing"
	"crypto/elliptic"

)

func TestZK(t *testing.T){
	user1 := User{
		NewKeys(),
		nil,
	}
	user2 := User{
		NewKeys(),
		nil,
	}
	curve := elliptic.P256()
	nonce,_ := rand.Int(rand.Reader, curve.Params().N)
	msg1 := MsgToBigInt([]byte("hey"))
	msg2 := MsgToBigInt([]byte("lort"))

	r1, _ := rand.Int(rand.Reader, user1.Keys.X)
	r2, _ := rand.Int(rand.Reader, user2.Keys.X)

	commit1 := user1.NewCommitment(msg1, r1)
	commit2 := user2.NewCommitment(msg2, r2)

	proof := NewEqProofP256(msg1, r1, r2, nonce, &user1.Keys.PublicKey, &user2.Keys.PublicKey)

	samemsg := proof.OpenP256(commit1, commit2, nonce, &user1.Keys.PublicKey, &user2.Keys.PublicKey)

	if !samemsg {
		t.Errorf("failed")
	} else {
		
	}


}
