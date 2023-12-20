package zklogstar

import (
	"crypto/rand"
	"github.com/fxamacker/cbor/v2"

	"MPC_ECDSA/pkg/BigInt"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/pedersen"
)

type Public struct {
	// C = Enc₀(x;ρ)
	// Encryption of x under the prover's key
	C *paillier.Ciphertext

	// X = x⋅G
	X curve.Point

	// G is the base point of the curve.
	// If G = nil, the default base point is used.
	G curve.Point

	Prover *paillier.PublicKey
	Aux    *pedersen.Parameters
}

type Private struct {
	// X is the plaintext of C and the discrete log of X.
	X *BigInt.Nat

	// Rho = ρ is nonce used to encrypt C.
	Rho *BigInt.Nat
}

type Commitment struct {
	// S = sˣ tᵘ (mod N)
	S *BigInt.Nat
	// A = Enc₀(alpha; r)
	A *paillier.Ciphertext
	// Y = α⋅G
	Y curve.Point
	// D = sᵃ tᵍ (mod N)
	D *BigInt.Nat
}

type Proof struct {
	group curve.Curve
	*Commitment
	// Z1 = α + e x
	Z1 *BigInt.Nat
	// Z2 = r ρᵉ mod N
	Z2 *BigInt.Nat
	// Z3 = γ + e μ
	Z3 *BigInt.Nat
}

// ProofCode is used in Cbor, composed of Natcode instead of Nat
// The purpose is to preserve the sign of Nat
type ProofCode struct {
	group curve.Curve
	*Commitment
	// Z1 = z₁ = α + ex
	Z1 *BigInt.NatCode
	// Z2 = z₂ = r⋅ρᵉ (mod N₀)
	Z2 *BigInt.NatCode
	// Z3 = z₃ = γ + eμ
	Z3 *BigInt.NatCode
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
	if !public.Prover.ValidateCiphertexts(p.A) {
		return false
	}
	if p.Y.IsIdentity() {
		return false
	}
	if !BigInt.IsValidNatModN(public.Prover.N(), p.Z2) {
		return false
	}
	return true
}

// NewProof generates a proof that:
//
//		X = x⋅G
//		C = Enc₀(x,ρ)
//	with:
//		Z₁ = α+ea (mod q)
//		Z₂ = β+eb (mod q)
//		z3 = γ + e μ
func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N()
	NModulus := public.Prover.Modulus()

	if public.G == nil {
		public.G = group.NewBasePoint()
	}

	alpha := sample.IntervalLEps(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)
	mu := sample.IntervalLN(rand.Reader)
	gamma := sample.IntervalLEpsN(rand.Reader)

	commitment := &Commitment{
		A: public.Prover.EncWithNonce(alpha, r),
		Y: group.NewScalar().SetNat(alpha.Mod1(group.Order())).Act(public.G),
		S: public.Aux.Commit(private.X, mu),
		D: public.Aux.Commit(alpha, gamma),
	}

	e, _ := challenge(hash, group, public, commitment)

	// z1 = α + e x,
	z1 := new(BigInt.Nat).SetNat(private.X)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)
	// z2 = r ρᵉ mod N,
	z2 := new(BigInt.Nat).ExpI(private.Rho, e, NModulus)
	z2.ModMul(z2, r, N)
	// z3 = γ + e μ,
	z3 := new(BigInt.Nat).Mul(e, mu, -1)
	z3.Add(z3, gamma, -1)

	return &Proof{
		group:      group,
		Commitment: commitment,
		Z1:         z1,
		Z2:         z2,
		Z3:         z3,
	}
}

// Verify checks a Proof is verified
func (p Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	if public.G == nil {
		public.G = p.group.NewBasePoint()
	}

	if !BigInt.IsInIntervalLEps(p.Z1) {
		return false
	}

	prover := public.Prover

	e, err := challenge(hash, p.group, public, p.Commitment)
	if err != nil {
		return false
	}

	if !public.Aux.Verify(p.Z1, p.Z3, e, p.D, p.S) {
		return false
	}

	{
		// lhs = Enc(z₁;z₂)
		lhs := prover.EncWithNonce(p.Z1, p.Z2)

		// rhs = (e ⊙ C) ⊕ A
		rhs := public.C.Clone().Mul(prover, e).Add(prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = [z₁]G
		lhs := p.group.NewScalar().SetNat(p.Z1.Mod1(p.group.Order())).Act(public.G)

		// rhs = Y + [e]X
		rhs := p.group.NewScalar().SetNat(e.Mod1(p.group.Order())).Act(public.X)
		rhs = rhs.Add(p.Y)

		if !lhs.Equal(rhs) {
			return false
		}

	}

	return true
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e *BigInt.Nat, err error) {
	err = hash.WriteAny(public.Aux, public.Prover, public.C, public.X, public.G,
		commitment.S, commitment.A, commitment.Y, commitment.D)
	e = sample.IntervalScalar(hash.Digest(), group)
	return
}

// Empty constructs a Proof with empty content
func Empty(group curve.Curve) *Proof {
	return &Proof{
		group:      group,
		Commitment: &Commitment{Y: group.NewPoint()},
	}
}

// EmptyCode constructs a ProofCode with empty content
func EmptyCode(group curve.Curve) *ProofCode {
	return &ProofCode{
		group:      group,
		Commitment: &Commitment{Y: group.NewPoint()},
	}
}

// ProofToCode converts a Proof to a ProofCode
func ProofToCode(p *Proof) *ProofCode {
	z := new(ProofCode)
	z.group = p.group
	z.Commitment = p.Commitment
	z.Z1 = p.Z1.MarshalNat()
	z.Z2 = p.Z2.MarshalNat()
	z.Z3 = p.Z3.MarshalNat()
	return z
}

// CodeToProof converts a ProofCode to Proof
func CodeToProof(p *ProofCode) *Proof {
	z := new(Proof)
	z.group = p.group
	z.Commitment = p.Commitment
	z.Z1 = new(BigInt.Nat).UnmarshalNat(p.Z1)
	z.Z2 = new(BigInt.Nat).UnmarshalNat(p.Z2)
	z.Z3 = new(BigInt.Nat).UnmarshalNat(p.Z3)
	return z
}

// NewProofMal generates a new Proof and Marshal it, return the Proofbuf
func NewProofMal(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proofbuf {
	proof := NewProof(group, hash, public, private)
	proofcode := ProofToCode(proof)
	buf, _ := cbor.Marshal(proofcode)
	proofbuf := new(Proofbuf)
	proofbuf.Malbuf = buf
	return proofbuf
}

// VerifyMal can verify a Proof in Proofbuf Type
func (p *Proofbuf) VerifyMal(group curve.Curve, hash *hash.Hash, public Public) bool {
	// proofcode := &ProofCode{}
	proofcode := EmptyCode(group)
	cbor.Unmarshal(p.Malbuf, proofcode)
	proof := CodeToProof(proofcode)
	return proof.Verify(hash, public)
}
