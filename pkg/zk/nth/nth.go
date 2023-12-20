// zknth is based on the zkenc package,
// and can be seen as the special case where the ciphertext encrypts the "0" value.
package zknth

import (
	"crypto/rand"
	"github.com/fxamacker/cbor/v2"

	"MPC_ECDSA/pkg/BigInt"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/sample"
)

type Public struct {
	// N
	N *paillier.PublicKey

	// R = r = ρᴺ (mod N²)
	R *BigInt.Nat
}

type Private struct {
	// Rho = ρ
	Rho *BigInt.Nat
}

type Commitment struct {
	// A = αᴺ (mod N²)
	A *BigInt.Nat
}

type Proof struct {
	Commitment
	// Z = αρᴺ (mod N²)
	Z *BigInt.Nat
}

// Proofbuf is used to store the byte stream during communication
type Proofbuf struct {
	Malbuf []byte
}

// IsValid checks whether a Proof is valid
func (p *Proof) IsValid(public Public) bool {
	if !BigInt.IsValidNatModN(public.N.N(), p.Z) {
		return false
	}

	if !BigInt.IsValidNatModN(public.N.ModulusSquared(), p.A) {
		return false
	}

	return true
}

// NewProof generates a proof that r = ρᴺ (mod N²).
func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	N := public.N.N()
	// α ← ℤₙˣ
	alpha := sample.UnitModN(rand.Reader, N)
	// A = αⁿ (mod n²)
	A := new(BigInt.Nat).Exp(alpha, N, public.N.ModulusSquared())
	commitment := Commitment{
		A: A,
	}
	e, _ := challenge(hash, public, commitment)
	// Z = αρᵉ (mod N)
	Z := new(BigInt.Nat).ExpI(private.Rho, e, public.N.Modulus())
	Z.ModMul(Z, alpha, N)
	return &Proof{
		Commitment: commitment,
		Z:          Z,
	}
}

// Verify checks a Proof is verified
func (p *Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	e, err := challenge(hash, public, p.Commitment)
	if err != nil {
		return false
	}

	NSquared := public.N.ModulusSquared()
	lhs := new(BigInt.Nat).Exp(p.Z, public.N.N(), NSquared)
	rhs := new(BigInt.Nat).ExpI(public.R, e, NSquared)
	rhs.ModMul(rhs, p.A, NSquared)
	if lhs.Eq(rhs) != 1 {
		return false
	}
	return true
}

func challenge(hash *hash.Hash, public Public, commitment Commitment) (e *BigInt.Nat, err error) {
	err = hash.WriteAny(public.N, public.R, commitment.A)
	e = sample.IntervalL(hash.Digest())
	return
}

// NewProofMal generates a new Proof and Marshal it, return the Proofbuf
func NewProofMal(hash *hash.Hash, public Public, private Private) *Proofbuf {
	proof := NewProof(hash, public, private)
	buf, _ := cbor.Marshal(proof)
	proofbuf := new(Proofbuf)
	proofbuf.Malbuf = buf
	return proofbuf
}

// VerifyMal can verify a Proof in Proofbuf Type
func (p *Proofbuf) VerifyMal(hash *hash.Hash, public Public) bool {
	proof := &Proof{}
	// proof := Empty(group)
	cbor.Unmarshal(p.Malbuf, proof)
	return proof.Verify(hash, public)
}
