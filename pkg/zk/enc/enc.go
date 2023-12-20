package zkenc

import (
	"MPC_ECDSA/pkg/math/sample"
	"crypto/rand"
	"github.com/fxamacker/cbor/v2"

	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/BigInt"
	//"MPC_ECDSA/pkg/math/sample"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/pedersen"
)

type Public struct {
	// K = Enc₀(k;ρ)
	K *paillier.Ciphertext

	Prover *paillier.PublicKey
	Aux    *pedersen.Parameters
}
type Private struct {
	// K = k ∈ 2ˡ = Dec₀(K)
	// plaintext of K
	K *BigInt.Nat

	// Rho = ρ
	// nonce of K
	Rho *BigInt.Nat
}

type Commitment struct {
	// S = sᵏtᵘ
	S *BigInt.Nat
	// A = Enc₀ (α, r)
	A *paillier.Ciphertext
	// C = sᵃtᵍ
	C *BigInt.Nat
}

type Proof struct {
	*Commitment
	// Z₁ = α + e⋅k
	Z1 *BigInt.Nat
	// Z₂ = r ⋅ ρᵉ mod N₀
	Z2 *BigInt.Nat
	// Z₃ = γ + e⋅μ
	Z3 *BigInt.Nat
}

// ProofCode is used in Cbor, composed of Natcode instead of Nat
// The purpose is to preserve the sign of Nat
type ProofCode struct {
	*Commitment
	// Z₁ = α + e⋅k
	Z1 *BigInt.NatCode
	// Z₂ = r ⋅ ρᵉ mod N₀
	Z2 *BigInt.NatCode
	// Z₃ = γ + e⋅μ
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
	if !BigInt.IsValidNatModN(public.Prover.N(), p.Z2) {
		return false
	}
	return true
}

// NewProof generates a proof that:
//
//		k∈±2l
//	with:
//		z1 = e•k+α
//		z2 = ρ⋅rᵉ
//		z3 = e•μ+γ
func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N()
	NModulus := public.Prover.Modulus()

	alpha := sample.IntervalLEps(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)
	mu := sample.IntervalLN(rand.Reader)
	gamma := sample.IntervalLEpsN(rand.Reader)

	A := public.Prover.EncWithNonce(alpha, r)

	commitment := &Commitment{
		S: public.Aux.Commit(private.K, mu),
		A: A,
		C: public.Aux.Commit(alpha, gamma),
	}

	e, _ := challenge(hash, group, public, commitment)

	// z1 = e•k+α
	z1 := new(BigInt.Nat).SetNat(private.K)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)

	// z2 = ρ⋅rᵉ
	z2 := new(BigInt.Nat).ExpI(private.Rho, e, NModulus)
	z2.ModMul(z2, r, N)

	// z3 = e•μ+γ
	z3 := new(BigInt.Nat).Mul(e, mu, -1)
	z3.Add(z3, gamma, -1)

	return &Proof{
		Commitment: commitment,
		Z1:         z1,
		Z2:         z2,
		Z3:         z3,
	}
}

// Verify checks a Proof is verified
func (p Proof) Verify(group curve.Curve, hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	prover := public.Prover

	if !BigInt.IsInIntervalLEps(p.Z1) {
		return false
	}

	e, err := challenge(hash, group, public, p.Commitment)
	if err != nil {
		return false
	}

	if !public.Aux.Verify(p.Z1, p.Z3, e, p.C, p.S) {
		return false
	}

	{
		// lhs = Enc(z₁;z₂)
		lhs := prover.EncWithNonce(p.Z1, p.Z2)

		// rhs = (e ⊙ K) ⊕ A
		rhs := public.K.Clone().Mul(prover, e).Add(prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e *BigInt.Nat, err error) {
	err = hash.WriteAny(public.Aux, public.Prover, public.K,
		commitment.S, commitment.A, commitment.C)
	e = sample.IntervalScalar(hash.Digest(), group)
	return
}

// ProofToCode converts a Proof to a ProofCode
func ProofToCode(p *Proof) *ProofCode {
	z := new(ProofCode)
	z.Commitment = p.Commitment
	z.Z1 = p.Z1.MarshalNat()
	z.Z2 = p.Z2.MarshalNat()
	z.Z3 = p.Z3.MarshalNat()
	return z
}

// CodeToProof converts a ProofCode to Proof
func CodeToProof(p *ProofCode) *Proof {
	z := new(Proof)
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
	proofcode := &ProofCode{}
	//proofcode := EmptyCode(group)
	cbor.Unmarshal(p.Malbuf, proofcode)
	proof := CodeToProof(proofcode)
	return proof.Verify(group, hash, public)
}
