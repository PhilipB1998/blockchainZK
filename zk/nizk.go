package zk

import (
	"crypto"
	"crypto/elliptic"
	"crypto/hmac"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/ec"
)

type Proof struct {
	H         *ec.GroupElement
	Generator *ec.GroupElement
	U         *ec.GroupElement
	Challenge *big.Int
	Z         *big.Int

	group *ec.Group
	hash  crypto.Hash
}

func MakeProof(hash crypto.Hash, secret_x *big.Int) *Proof {
	curve := ec.P256 //wrapper
	group := ec.NewGroup(curve)
	r := common.GetRandomInt(group.Q)   // random r from Z_q
	generator := group.ExpBaseG(r)      // generator g for group
	h := group.Exp(generator, secret_x) // h = g^x
	u := group.Exp(generator, r)        // u = g^r

	Hash := hash.New()
	Hash.Write(elliptic.Marshal(ec.GetCurve(curve), generator.X, generator.Y))
	Hash.Write(elliptic.Marshal(ec.GetCurve(curve), h.X, h.Y))
	Hash.Write(elliptic.Marshal(ec.GetCurve(curve), u.X, u.Y))
	cBytes := Hash.Sum(nil)

	// Doing z = r - cx instead of r = r + cx saves an inversion computation on the verification side
	c := new(big.Int).SetBytes(cBytes)
	c.Mod(c, group.Q) // c = c mod group-order

	z := new(big.Int).Neg(c)
	z.Mul(z, secret_x) // z = -c * x
	z.Add(z, r)        // z = z + r (or z = r - cx (as this is what it currently is))
	z.Mod(z, group.Q)  // z mod group-order

	return &Proof{
		H:         h,
		Generator: generator,
		U:         u,
		Challenge: c,
		Z:         z,

		group: group,
		hash:  hash,
	}
}

func (proof *Proof) VerifyProof() bool {
	group := proof.group
	curve := ec.P256
	a := group.Exp(proof.Generator, proof.Z) //g^z ok
	b := group.Exp(proof.H, proof.Challenge)    //h^c
	c := group.Mul(a, b)              //u * h^c

	Hash := proof.hash.New()
	Hash.Write(elliptic.Marshal(ec.GetCurve(curve), proof.Generator.X, proof.Generator.Y))
	Hash.Write(elliptic.Marshal(ec.GetCurve(curve), proof.H.X, proof.H.Y))
	Hash.Write(elliptic.Marshal(ec.GetCurve(curve), c.X, c.Y))
	cBytes := Hash.Sum(nil)

	return hmac.Equal(cBytes, proof.Challenge.Bytes())
}
