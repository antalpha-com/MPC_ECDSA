package zkelog

import (
	"crypto/rand"
	"github.com/fxamacker/cbor/v2"

	"MPC_ECDSA/internal/elgamal"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"
)

type Public struct {
	// E = (L=λ⋅G, M=y⋅G+λ⋅X)
	E *elgamal.Ciphertext

	// ElGamalPublic = X
	ElGamalPublic elgamal.PublicKey

	// Base = H
	Base curve.Point

	// Y = y⋅H
	Y curve.Point
}

type Private struct {
	// Y = y
	Y curve.Scalar

	// Lambda = λ
	Lambda curve.Scalar
}

type Commitment struct {
	// A = α⋅G
	A curve.Point

	// N = m⋅G+α⋅X
	N curve.Point

	// B = m⋅H
	B curve.Point
}

type Proof struct {
	group curve.Curve
	*Commitment

	// Z = α+eλ (mod q)
	Z curve.Scalar

	// U = m+ey (mod q)
	U curve.Scalar
}

// Proofbuf is used to store the byte stream during communication
type Proofbuf struct {
	Malbuf []byte
}

// IsValid checks whether a Proof is valid
func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if p.A.IsIdentity() || p.N.IsIdentity() || p.B.IsIdentity() {
		return false
	}
	if p.Z.IsZero() || p.U.IsZero() {
		return false
	}
	return true
}

// NewProof generates a proof that:
//
//		A = α⋅G
//		N = m⋅G+α⋅X
//		B = m⋅H
//	with:
//		Z = α+eλ (mod q)
//		U = m+ey (mod q)
func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	alpha := sample.Scalar(rand.Reader, group)
	m := sample.Scalar(rand.Reader, group)

	commitment := &Commitment{
		A: alpha.ActOnBase(),                                  // A = α⋅G
		N: m.ActOnBase().Add(alpha.Act(public.ElGamalPublic)), // N = m⋅G+α⋅X
		B: m.Act(public.Base),                                 // B = m⋅H
	}
	e, _ := challenge(hash, group, public, commitment)

	return &Proof{
		group:      group,
		Commitment: commitment,
		Z:          group.NewScalar().Set(e).Mul(private.Lambda).Add(alpha), // Z = α+eλ (mod q)
		U:          group.NewScalar().Set(e).Mul(private.Y).Add(m),          // U = m+ey (mod q)
	}
}

// Verify checks a Proof is verified
func (p Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	e, err := challenge(hash, p.group, public, p.Commitment)
	if err != nil {
		return false
	}

	{
		lhs := p.Z.ActOnBase()            // lhs = z⋅G
		rhs := e.Act(public.E.L).Add(p.A) // rhs = A+e⋅L
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		lhs := p.U.ActOnBase().Add(p.Z.Act(public.ElGamalPublic)) // lhs = u⋅G+z⋅X
		rhs := e.Act(public.E.M).Add(p.N)                         // rhs = N+e⋅M
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		lhs := p.U.Act(public.Base)     // lhs = u⋅H
		rhs := e.Act(public.Y).Add(p.B) // rhs = B+e⋅Y
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e curve.Scalar, err error) {
	err = hash.WriteAny(public.E, public.ElGamalPublic, public.Y, public.Base,
		commitment.A, commitment.N, commitment.B)
	e = sample.Scalar(hash.Digest(), group)
	return
}

// Empty constructs a Proof with empty content
func Empty(group curve.Curve) *Proof {
	return &Proof{
		group: group,
		Commitment: &Commitment{
			A: group.NewPoint(),
			N: group.NewPoint(),
			B: group.NewPoint(),
		},
		Z: group.NewScalar(),
		U: group.NewScalar(),
	}
}

// NewProofMal generates a new Proof and Marshal it, return the Proofbuf
func NewProofMal(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proofbuf {
	proof := NewProof(group, hash, public, private)
	buf, _ := cbor.Marshal(proof)
	proofbuf := new(Proofbuf)
	proofbuf.Malbuf = buf
	return proofbuf
}

// VerifyMal can verify a Proof in Proofbuf Type
func (p *Proofbuf) VerifyMal(group curve.Curve, hash *hash.Hash, public Public) bool {
	//proofcode := &ProofCode{}
	proof := Empty(group)
	cbor.Unmarshal(p.Malbuf, proof)
	return proof.Verify(hash, public)
}
