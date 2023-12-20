package zkaffg

import (
	"MPC_ECDSA/pkg/BigInt"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/pedersen"
	"crypto/rand"
	"github.com/fxamacker/cbor/v2"
)

type Public struct {
	// Kv is a ciphertext encrypted with Nᵥ
	// Original name: C
	Kv *paillier.Ciphertext

	// Dv = (x ⨀ Kv) ⨁ Encᵥ(y;s)
	Dv *paillier.Ciphertext

	// Fp = Encₚ(y;r)
	// Original name: Y
	Fp *paillier.Ciphertext

	// Xp = gˣ
	Xp curve.Point

	// Prover = Nₚ
	// Verifier = Nᵥ
	Prover, Verifier *paillier.PublicKey
	Aux              *pedersen.Parameters
}

type Private struct {
	// X = x
	X *BigInt.Nat
	// Y = y
	Y *BigInt.Nat
	// S = s
	// Original name: ρ
	S *BigInt.Nat
	// R = r
	// Original name: ρy
	R *BigInt.Nat
}
type Commitment struct {
	// A = (α ⊙ C) ⊕ Encᵥ(β, ρ)
	A *paillier.Ciphertext
	// Bₓ = α⋅G
	Bx curve.Point
	// By = Encₚ(β, ρy)
	By *paillier.Ciphertext
	// E = sᵃ tᵍ (mod N)
	E *BigInt.Nat
	// S = sˣ tᵐ (mod N)
	S *BigInt.Nat
	// F = sᵇ tᵈ (mod N)
	F *BigInt.Nat
	// T = sʸ tᵘ (mod N)
	T *BigInt.Nat
}

type Proof struct {
	group curve.Curve
	*Commitment
	// Z1 = Z₁ = α + e⋅x
	Z1 *BigInt.Nat
	// Z2 = Z₂ = β + e⋅y
	Z2 *BigInt.Nat
	// Z3 = Z₃ = γ + e⋅m
	Z3 *BigInt.Nat
	// Z4 = Z₄ = δ + e⋅μ
	Z4 *BigInt.Nat
	// W = w = ρ⋅sᵉ (mod N₀)
	W *BigInt.Nat
	// Wy = wy = ρy⋅rᵉ (mod N₁)
	Wy *BigInt.Nat
}

// ProofCode is used in Cbor, composed of Natcode instead of Nat
// The purpose is to preserve the sign of Nat
type ProofCode struct {
	group curve.Curve
	*Commitment
	// Z1 = Z₁ = α + e⋅x
	Z1 *BigInt.NatCode
	// Z2 = Z₂ = β + e⋅y
	Z2 *BigInt.NatCode
	// Z3 = Z₃ = γ + e⋅m
	Z3 *BigInt.NatCode
	// Z4 = Z₄ = δ + e⋅μ
	Z4 *BigInt.NatCode
	// W = w = ρ⋅sᵉ (mod N₀)
	W *BigInt.NatCode
	// Wy = wy = ρy⋅rᵉ (mod N₁)
	Wy *BigInt.NatCode
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
	if !public.Verifier.ValidateCiphertexts(p.A) {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.By) {
		return false
	}
	if !BigInt.IsValidNatModN(public.Prover.N(), p.Wy) {
		return false
	}
	if !BigInt.IsValidNatModN(public.Verifier.N(), p.W) {
		return false
	}
	if p.Bx.IsIdentity() {
		return false
	}
	return true
}

// NewProof generates a proof that:
//
//		Cᵃ mod N₀ = α ⊙ Kv
//		Enc₀(β,ρ) ⊕ (α ⊙ Kv)
//	with:
//		z1 = e•x+α
//		z2 = e•y+β
//		z3 = e•m+γ
//		z4 = e•μ+δ
//		w = ρ⋅sᵉ mod N₀
//		wy = ρy⋅rᵉ  mod N₁
func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	N0 := public.Verifier.N()
	N1 := public.Prover.N()
	N0Modulus := public.Verifier.Modulus()
	N1Modulus := public.Prover.Modulus()

	verifier := public.Verifier
	prover := public.Prover

	alpha := sample.IntervalLEps(rand.Reader)
	beta := sample.IntervalLPrimeEps(rand.Reader)

	rho := sample.UnitModN(rand.Reader, N0)
	rhoY := sample.UnitModN(rand.Reader, N1)

	gamma := sample.IntervalLEpsN(rand.Reader)
	m := sample.IntervalLN(rand.Reader)
	delta := sample.IntervalLEpsN(rand.Reader)
	mu := sample.IntervalLN(rand.Reader)

	cAlpha := public.Kv.Clone().Mul(verifier, alpha) // = Cᵃ mod N₀ = α ⊙ Kv
	//cAlpha := public.Kv.Clone()
	//cAlpha.Mul(verifier, alpha) // = Cᵃ mod N₀ = α ⊙ Kv

	A := verifier.EncWithNonce(beta, rho).Add(verifier, cAlpha) // = Enc₀(β,ρ) ⊕ (α ⊙ Kv)

	E := public.Aux.Commit(alpha, gamma)
	S := public.Aux.Commit(private.X, m)
	F := public.Aux.Commit(beta, delta)
	T := public.Aux.Commit(private.Y, mu)
	commitment := &Commitment{
		A:  A,
		Bx: group.NewScalar().SetNat(alpha.Mod1(group.Order())).ActOnBase(),
		By: prover.EncWithNonce(beta, rhoY),
		E:  E,
		S:  S,
		F:  F,
		T:  T,
	}

	e, _ := challenge(hash, group, public, commitment)

	// e•x+α
	z1 := new(BigInt.Nat).SetNat(private.X)

	z1.Mul(e, z1, -1)

	z1.Add(z1, alpha, -1)

	// e•y+β
	z2 := new(BigInt.Nat).SetNat(private.Y)
	z2.Mul(e, z2, -1)
	z2.Add(z2, beta, -1)
	// e•m+γ
	z3 := new(BigInt.Nat).Mul(e, m, -1)
	z3.Add(z3, gamma, -1)
	// e•μ+δ
	z4 := new(BigInt.Nat).Mul(e, mu, -1)
	z4.Add(z4, delta, -1)
	// ρ⋅sᵉ mod N₀
	w := new(BigInt.Nat).ExpI(private.S, e, N0Modulus)
	w.ModMul(w, rho, N0)
	// ρy⋅rᵉ  mod N₁
	wY := new(BigInt.Nat).ExpI(private.R, e, N1Modulus)
	wY.ModMul(wY, rhoY, N1)

	return &Proof{
		group:      group,
		Commitment: commitment,
		Z1:         z1,
		Z2:         z2,
		Z3:         z3,
		Z4:         z4,
		W:          w,
		Wy:         wY,
	}
}

// Verify checks a Proof is verified
func (p Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	verifier := public.Verifier
	prover := public.Prover

	if !sample.IsInIntervalLEps(p.Z1) {
		return false
	}
	if !sample.IsInIntervalLPrimeEps(p.Z2) {
		return false
	}

	e, err := challenge(hash, p.group, public, p.Commitment)
	if err != nil {
		return false
	}

	if !public.Aux.Verify(p.Z1, p.Z3, e, p.E, p.S) {
		return false
	}

	if !public.Aux.Verify(p.Z2, p.Z4, e, p.F, p.T) {
		return false
	}

	{
		// tmp = z₁ ⊙ Kv
		// lhs = Enc₀(z₂;w) ⊕ z₁ ⊙ Kv
		tmp := public.Kv.Clone().Mul(verifier, p.Z1)
		lhs := verifier.EncWithNonce(p.Z2, p.W).Add(verifier, tmp)

		// rhs = (e ⊙ Dv) ⊕ A
		rhs := public.Dv.Clone().Mul(verifier, e).Add(verifier, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = [z₁]G
		lhs := p.group.NewScalar().SetNat(p.Z1.Mod1(p.group.Order())).ActOnBase()

		// rhsPt = Bₓ + [e]Xp
		rhs := p.group.NewScalar().SetNat(e.Mod1(p.group.Order())).Act(public.Xp)
		rhs = rhs.Add(p.Bx)

		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = Enc₁(z₂; wy)
		lhs := prover.EncWithNonce(p.Z2, p.Wy)
		// rhs = (e ⊙ Fp) ⊕ By
		rhs := public.Fp.Clone().Mul(prover, e).Add(prover, p.By)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e *BigInt.Nat, err error) {
	err = hash.WriteAny(public.Aux, public.Prover, public.Verifier,
		public.Kv, public.Dv, public.Fp, public.Xp,
		commitment.A, commitment.Bx, commitment.By,
		commitment.E, commitment.S, commitment.F, commitment.T)

	e = sample.IntervalScalar(hash.Digest(), group)
	return
}

// Empty constructs a Proof with empty content
func Empty(group curve.Curve) *Proof {
	return &Proof{
		group:      group,
		Commitment: &Commitment{Bx: group.NewPoint()},
	}
}

// EmptyCode constructs a ProofCode with empty content
func EmptyCode(group curve.Curve) *ProofCode {
	return &ProofCode{
		group:      group,
		Commitment: &Commitment{Bx: group.NewPoint()},
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
	z.Z4 = p.Z4.MarshalNat()
	z.W = p.W.MarshalNat()
	z.Wy = p.Wy.MarshalNat()
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
	z.Z4 = new(BigInt.Nat).UnmarshalNat(p.Z4)
	z.W = new(BigInt.Nat).UnmarshalNat(p.W)
	z.Wy = new(BigInt.Nat).UnmarshalNat(p.Wy)
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
