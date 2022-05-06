package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
)

type User struct {
	Keys       *ecdsa.PrivateKey
	Commitment *ecdsa.PublicKey
}

type EqProof struct {
	C  *big.Int
	D  *big.Int
	D1 *big.Int
	D2 *big.Int
}

type Commitment struct {
	X *big.Int
	Y *big.Int
}

func NewKeys() *ecdsa.PrivateKey {
	a, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return a
}

func (u *User) NewCommitment(x, r *big.Int) *Commitment {
	curve := elliptic.P256()
	cx, cy := curve.ScalarBaseMult(x.Bytes())
	dx, dy := curve.ScalarMult(u.Keys.X, u.Keys.Y, r.Bytes())
	xx, yy := curve.Add(cx, cy, dx, dy)
	return &Commitment{
		xx, yy,
	}
}

func NewEqProofP256(x, r1, r2, nonce *big.Int, pk1 *ecdsa.PublicKey, pk2 *ecdsa.PublicKey) *EqProof {
	curve := elliptic.P256()
	curveParams := curve.Params()
	q1x := pk1.X
	q1y := pk1.Y
	q2x := pk2.X
	q2y := pk2.Y
	w, _ := rand.Int(rand.Reader, curveParams.N)
	n1, _ := rand.Int(rand.Reader, curveParams.N)
	n2, _ := rand.Int(rand.Reader, curveParams.N)

	w1x1, w1y1 := curveParams.ScalarBaseMult(w.Bytes())
	w1x2, w1y2 := curveParams.ScalarMult(q1x, q1y, n1.Bytes())
	w1x, w1y := curveParams.Add(w1x1, w1y1, w1x2, w1y2)

	w2x2, w2y2 := curveParams.ScalarMult(q2x, q2y, n2.Bytes())
	w2x, w2y := curveParams.Add(w1x1, w1y1, w2x2, w2y2)

	hasher := sha512.New384()
	_, _ = hasher.Write(w1x.Bytes())
	_, _ = hasher.Write(w1y.Bytes())
	_, _ = hasher.Write(w2x.Bytes())
	_, _ = hasher.Write(w2y.Bytes())
	_, _ = hasher.Write(nonce.Bytes())

	c := new(big.Int).SetBytes(hasher.Sum(nil))
	c.Mod(c, curveParams.N)

	d := new(big.Int).Sub(w, new(big.Int).Mul(c, x))
	d.Mod(d, curveParams.N)

	d1 := new(big.Int).Sub(n1, new(big.Int).Mul(c, r1))
	d1.Mod(d1, curveParams.N)

	d2 := new(big.Int).Sub(n2, new(big.Int).Mul(c, r2))
	d2.Mod(d2, curveParams.N)

	return &EqProof{
		c, d, d1, d2,
	}
}

func (eq *EqProof) OpenP256(b, c *Commitment, nonce *big.Int, pk1 *ecdsa.PublicKey, pk2 *ecdsa.PublicKey) bool {
	curve1 := elliptic.P256()
	curve := curve1.Params()
	q1x := pk1.X
	q1y := pk1.Y
	q2x := pk2.X
	q2y := pk2.Y

	dx, dy := curve.ScalarBaseMult(eq.D.Bytes())
	lhsx1, lhsy1 := curve.ScalarMult(q1x, q1y, eq.D1.Bytes())
	lhsx2, lhsy2 := curve.ScalarMult(b.X, b.Y, eq.C.Bytes())
	lhsx1, lhsy1 = curve.Add(dx, dy, lhsx1, lhsy1)
	lhsx, lhsy := curve.Add(lhsx2, lhsy2, lhsx1, lhsy1)

	rhsx1, rhsy1 := curve.ScalarMult(q2x, q2y, eq.D2.Bytes())
	rhsx2, rhsy2 := curve.ScalarMult(c.X, c.Y, eq.C.Bytes())
	rhsx1, rhsy1 = curve.Add(dx, dy, rhsx1, rhsy1)
	rhsx, rhsy := curve.Add(rhsx2, rhsy2, rhsx1, rhsy1)

	hasher := sha512.New384()
	_, _ = hasher.Write(lhsx.Bytes())
	_, _ = hasher.Write(lhsy.Bytes())
	_, _ = hasher.Write(rhsx.Bytes())
	_, _ = hasher.Write(rhsy.Bytes())
	_, _ = hasher.Write(nonce.Bytes())

	chal := new(big.Int).SetBytes(hasher.Sum(nil))
	chal.Mod(chal, curve.N)

	return chal.Cmp(eq.C) == 0
}

func MsgToBigInt(msg []byte) *big.Int { // This is not secure
	curve1 := elliptic.P256()
	curve := curve1.Params()
	hashedMsg := sha512.Sum384(msg)
	hashedMsgToBigInt := new(big.Int).SetBytes(hashedMsg[:])
	qs := new(big.Int).Mod(hashedMsgToBigInt, curve.N)
	qs1 := new(big.Int).Mod(qs, curve.B)

	return qs1
}


func main() {
	user1 := User{
		NewKeys(),
		nil,
	}

	user2 := User{
		NewKeys(),
		nil,
	}	
	fmt.Println(".-------------------------------------------.")
	fmt.Println("|  Hi! I'm the commitment equality bunny!   |")
	fmt.Println("'-------------------------------------------'")
	fmt.Println("    ^                                 	(\\_/)")
	fmt.Println("    '-------------------------------- 	(O.o)")
	fmt.Println("                                      	(> <)")
	fmt.Println()
	fmt.Println("Please input message for first commitment: ")
	curve := elliptic.P256()
	nonce, _ := rand.Int(rand.Reader, curve.Params().N)
	
	reader := bufio.NewReader(os.Stdin)
	input, err :=  reader.ReadString('\n')
	if err != nil {
		log.Panic(err)
		return
	}
	
	fmt.Printf("%s %v", "Creating first commitment for message: ", input )

	input = strings.TrimSuffix(input, "\n")
	inputToByte := []byte(input)
	inputToBigInt := MsgToBigInt(inputToByte)
	r1, _ := rand.Int(rand.Reader, curve.Params().N)
	commit1 := user1.NewCommitment(inputToBigInt, r1)
	

	fmt.Printf("%s %#v", "Produced following first commitment: ", commit1 )

	//SECOND COMMIT
	fmt.Println("Please input message for second commitment: ")

	input2, err :=  reader.ReadString('\n')
	if err != nil {
		log.Panic(err)
		return
	}

	fmt.Printf("%s %v", "Creating second commitment for message: ", input2 )
	
	input2 = strings.TrimSuffix(input2, "\n")
	input2ToByte := []byte(input2)
	input2ToBigInt := MsgToBigInt(input2ToByte)
	r2, _ := rand.Int(rand.Reader, curve.Params().N)
	commit2 := user2.NewCommitment(input2ToBigInt, r2)

	fmt.Printf("%s %#v", "Produced following second commitment: ", commit2 )


	// EQUALITY PROOF
	fmt.Println("Creating new equality proof")
	proof := NewEqProofP256(inputToBigInt, r1, r2, nonce,  &user1.Keys.PublicKey, &user2.Keys.PublicKey)
	sameMsg := proof.OpenP256(commit1, commit2, nonce, &user1.Keys.PublicKey,  &user2.Keys.PublicKey)
	
	fmt.Println("Commits holds the same message: ", sameMsg)

	
}









