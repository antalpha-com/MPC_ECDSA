package zkdec

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
	// C = Enc₀(y;ρ)
	C *paillier.Ciphertext

	// X = y (mod q)
	X curve.Scalar

	// Prover = N₀
	Prover *paillier.PublicKey
	Aux    *pedersen.Parameters
}

type Private struct {
	// Y = y
	Y *BigInt.Nat

	// Rho = ρ
	Rho *BigInt.Nat
}

type Commitment struct {
	// S = sʸ tᵘ
	S *BigInt.Nat
	// T = sᵃ tᵛ
	T *BigInt.Nat
	// A = Enc₀(α; r)
	A *paillier.Ciphertext
	// Gamma = α (mod q)
	Gamma curve.Scalar
}

type Proof struct {
	group curve.Curve
	*Commitment
	// Z1 = α + e•y
	Z1 *BigInt.Nat
	// Z2 = ν + e•μ
	Z2 *BigInt.Nat
	// W  = r ρ ᵉ (mod N₀)
	W *BigInt.Nat
}

// ProofCode is used in Cbor, composed of Natcode instead of Nat
// The purpose is to preserve the sign of Nat
type ProofCode struct {
	group curve.Curve
	*Commitment
	//  Z1 = α + e•y
	Z1 *BigInt.NatCode
	// Z2 = ν + e•μ
	Z2 *BigInt.NatCode
	// W  = r ρ ᵉ (mod N₀)
	W *BigInt.NatCode
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
	if p.Gamma == nil || p.Gamma.IsZero() {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.A) {
		return false
	}
	if !BigInt.IsValidNatModN(public.Prover.N(), p.W) {
		return false
	}
	return true
}

// NewProof generates a proof that:
//
//		x=y mod q
//		C = Enc₀(y,ρ)
//	with:
//		z1 = e•y+α
//		z2 = e•μ + ν
//		w = ρ^e•r mod N₀
func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N()
	NModulus := public.Prover.Modulus()
	alpha := sample.IntervalLEps(rand.Reader)

	mu := sample.IntervalLN(rand.Reader)
	nu := sample.IntervalLEpsN(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)

	gamma := group.NewScalar().SetNat(alpha.Mod1(group.Order()))

	commitment := &Commitment{
		S:     public.Aux.Commit(private.Y, mu),
		T:     public.Aux.Commit(alpha, nu),
		A:     public.Prover.EncWithNonce(alpha, r),
		Gamma: gamma,
	}

	e, _ := challenge(hash, group, public, commitment)

	// z₁ = e•y+α
	z1 := new(BigInt.Nat).SetNat(private.Y)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)
	// z₂ = e•μ + ν
	z2 := new(BigInt.Nat).Mul(e, mu, -1)
	z2.Add(z2, nu, -1)
	// w = ρ^e•r mod N₀
	w := new(BigInt.Nat).ExpI(private.Rho, e, NModulus)
	w.ModMul(w, r, N)

	return &Proof{
		group:      group,
		Commitment: commitment,
		Z1:         z1,
		Z2:         z2,
		W:          w,
	}
}

// Verify checks a Proof is verified
func (p *Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	e, err := challenge(hash, p.group, public, p.Commitment)
	if err != nil {
		return false
	}

	if !public.Aux.Verify(p.Z1, p.Z2, e, p.T, p.S) {
		return false
	}

	{
		// lhs = Enc₀(z₁;w)
		lhs := public.Prover.EncWithNonce(p.Z1, p.W)

		// rhs = (e ⊙ C) ⊕ A
		rhs := public.C.Clone().Mul(public.Prover, e).Add(public.Prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = z₁ mod q
		lhs := p.group.NewScalar().SetNat(p.Z1.Mod1(p.group.Order()))

		// rhs = e•x + γ
		rhs := p.group.NewScalar().SetNat(e.Mod1(p.group.Order())).Mul(public.X).Add(p.Gamma)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e *BigInt.Nat, err error) {
	err = hash.WriteAny(public.Aux, public.Prover,
		public.C, public.X,
		commitment.S, commitment.T, commitment.A, commitment.Gamma)
	e = sample.IntervalScalar(hash.Digest(), group)
	return
}

// Empty constructs a Proof with empty content
func Empty(group curve.Curve) *Proof {
	return &Proof{group: group, Commitment: &Commitment{Gamma: group.NewScalar()}}
}

// Empty constructs a ProofCode with empty content
func EmptyCode(group curve.Curve) *ProofCode {
	return &ProofCode{group: group, Commitment: &Commitment{Gamma: group.NewScalar()}}

}

// ProofToCode converts a Proof to a ProofCode
func ProofToCode(p *Proof) *ProofCode {
	z := new(ProofCode)
	z.group = p.group
	z.Commitment = p.Commitment
	z.Z1 = p.Z1.MarshalNat()
	z.Z2 = p.Z2.MarshalNat()
	z.W = p.W.MarshalNat()
	return z
}

// CodeToProof converts a ProofCode to Proof
func CodeToProof(p *ProofCode) *Proof {
	z := new(Proof)
	z.group = p.group
	z.Commitment = p.Commitment
	z.Z1 = new(BigInt.Nat).UnmarshalNat(p.Z1)
	z.Z2 = new(BigInt.Nat).UnmarshalNat(p.Z2)
	z.W = new(BigInt.Nat).UnmarshalNat(p.W)

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
	//proofcode := &ProofCode{}
	proofcode := EmptyCode(group)
	cbor.Unmarshal(p.Malbuf, proofcode)
	proof := CodeToProof(proofcode)
	return proof.Verify(hash, public)
}
