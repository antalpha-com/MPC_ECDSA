package zkaffp

import (
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/pedersen"
	"crypto/rand"
	"github.com/fxamacker/cbor/v2"

	//"MPC_ECDSA/pkg/math/curve"
	//"MPC_ECDSA/pkg/pedersen"
	"MPC_ECDSA/pkg/BigInt"
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

	// Xp = Encₚ(x;rₓ)
	Xp *paillier.Ciphertext

	// Prover = N₁
	// Verifier = N₀
	Prover, Verifier *paillier.PublicKey
	Aux              *pedersen.Parameters
}

type Private struct {
	// X ∈ ± 2ˡ
	X *BigInt.Nat
	// Y ∈ ± 2ˡº
	Y *BigInt.Nat
	// S = s
	// Original name: ρ
	S *BigInt.Nat
	// Rx = rₓ
	// Original name: ρx
	Rx *BigInt.Nat
	// R = r
	// Original name: ρy
	R *BigInt.Nat
}

type Commitment struct {
	// A = (α ⊙ Kv) ⊕ Enc₀(β; ρ)
	A *paillier.Ciphertext
	// Bx = Enc₁(α;ρₓ)
	Bx *paillier.Ciphertext
	// By = Enc₁(β;ρy)
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
	*Commitment
	// Z1 = Z₁ = α+ex
	Z1 *BigInt.Nat
	// Z2 = Z₂ = β+ey
	Z2 *BigInt.Nat
	// Z3 = Z₃ = γ+em
	Z3 *BigInt.Nat
	// Z4 = Z₄ = δ+eμ
	Z4 *BigInt.Nat
	// W = w = ρ⋅sᵉ (mod N₀)
	W *BigInt.Nat
	// Wx = wₓ = ρₓ⋅rₓᵉ (mod N₁)
	Wx *BigInt.Nat
	// Wy = wy = ρy ⋅rᵉ (mod N₁)
	Wy *BigInt.Nat
}

// ProofCode is used in Cbor, composed of Natcode instead of Nat
// The purpose is to preserve the sign of Nat
type ProofCode struct {
	*Commitment
	// Z1 = Z₁ = α + e⋅x
	Z1 *BigInt.NatCode
	// Z2 = Z₂ = β+ey
	Z2 *BigInt.NatCode
	// Z3 = Z₃ = γ+em
	Z3 *BigInt.NatCode
	// Z4 = Z₄ = δ+eμ
	Z4 *BigInt.NatCode
	// W = w = ρ⋅sᵉ (mod N₀)
	W *BigInt.NatCode
	// Wx = wₓ = ρₓ⋅rₓᵉ (mod N₁)
	Wx *BigInt.NatCode
	// Wy = wy = ρy ⋅rᵉ (mod N₁)
	Wy *BigInt.NatCode
}

// IsValid checks whether a Proof is valid
func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if !public.Verifier.ValidateCiphertexts(p.A) {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.Bx, p.By) {
		return false
	}
	if !BigInt.IsValidNatModN(public.Prover.N(), p.Wx, p.Wy) {
		return false
	}
	if !BigInt.IsValidNatModN(public.Verifier.N(), p.W) {
		return false
	}
	return true
}

// Proofbuf is used to store the byte stream during communication
type Proofbuf struct {
	Malbuf []byte
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
//		wx = ρₓ⋅rₓᵉ (mod N₁)
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
	rhoX := sample.UnitModN(rand.Reader, N1)
	rhoY := sample.UnitModN(rand.Reader, N1)

	gamma := sample.IntervalLEpsN(rand.Reader)
	m := sample.IntervalLN(rand.Reader)
	delta := sample.IntervalLEpsN(rand.Reader)
	mu := sample.IntervalLN(rand.Reader)

	//cAlpha := public.Kv.Clone()

	cAlpha := public.Kv.Clone().Mul(verifier, alpha) // = Cᵃ mod N₀ = α ⊙ Kv
	//cAlpha.Mul(verifier, alpha) // = Cᵃ mod N₀ = α ⊙ Kv
	//cAlpha := public.Kv.Clone().Mul(verifier, alpha)            // = Cᵃ mod N₀ = α ⊙ Kv
	A := verifier.EncWithNonce(beta, rho).Add(verifier, cAlpha) // = Enc₀(β,ρ) ⊕ (α ⊙ Kv)

	E := public.Aux.Commit(alpha, gamma)
	S := public.Aux.Commit(private.X, m)
	F := public.Aux.Commit(beta, delta)
	T := public.Aux.Commit(private.Y, mu)
	commitment := &Commitment{
		A:  A,
		Bx: prover.EncWithNonce(alpha, rhoX),
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
	// ρ⋅sᵉ (mod N₀)
	w := new(BigInt.Nat).ExpI(private.S, e, N0Modulus)
	w.ModMul(w, rho, N0)
	// ρₓ⋅rₓᵉ (mod N₁)
	wX := new(BigInt.Nat).ExpI(private.Rx, e, N1Modulus)
	wX.ModMul(wX, rhoX, N1)
	// ρy⋅rᵉ (mod N₁)
	wY := new(BigInt.Nat).ExpI(private.R, e, N1Modulus)
	wY.ModMul(wY, rhoY, N1)

	return &Proof{
		Commitment: commitment,
		Z1:         z1,
		Z2:         z2,
		Z3:         z3,
		Z4:         z4,
		W:          w,
		Wx:         wX,
		Wy:         wY,
	}
}

// Verify checks a Proof is verified
func (p Proof) Verify(group curve.Curve, hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	verifier := public.Verifier
	prover := public.Prover

	if !BigInt.IsInIntervalLEps(p.Z1) {
		return false
	}
	if !BigInt.IsInIntervalLPrimeEps(p.Z2) {
		return false
	}

	e, err := challenge(hash, group, public, p.Commitment)
	if err != nil {
		return false
	}

	{
		tmp := public.Kv.Clone().Mul(verifier, p.Z1)                 // tmp = z₁ ⊙ Kv
		lhs := verifier.EncWithNonce(p.Z2, p.W).Add(verifier, tmp)   // lhs = Enc₀(z₂;w) ⊕ (z₁ ⊙ Kv)
		rhs := public.Dv.Clone().Mul(verifier, e).Add(verifier, p.A) // rhs = (e ⊙ Dv) ⊕ A
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		lhs := prover.EncWithNonce(p.Z1, p.Wx)                    // lhs = Enc₁(z₁; wₓ)
		rhs := public.Xp.Clone().Mul(prover, e).Add(prover, p.Bx) // rhs = (e ⊙ Xp) ⊕ Bₓ
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		lhs := prover.EncWithNonce(p.Z2, p.Wy)                    // lhs = Enc₁(z₂; wy)
		rhs := public.Fp.Clone().Mul(prover, e).Add(prover, p.By) // rhs = (e ⊙ Fp) ⊕ By
		if !lhs.Equal(rhs) {
			return false
		}
	}

	if !public.Aux.Verify(p.Z1, p.Z3, e, p.E, p.S) {
		return false
	}

	if !public.Aux.Verify(p.Z2, p.Z4, e, p.F, p.T) {
		return false
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

// ProofToCode converts a Proof to a ProofCode
func ProofToCode(p *Proof) *ProofCode {
	z := new(ProofCode)
	z.Commitment = p.Commitment
	z.Z1 = p.Z1.MarshalNat()
	z.Z2 = p.Z2.MarshalNat()
	z.Z3 = p.Z3.MarshalNat()
	z.Z4 = p.Z4.MarshalNat()
	z.W = p.W.MarshalNat()
	z.Wx = p.Wx.MarshalNat()
	z.Wy = p.Wy.MarshalNat()
	return z
}

// CodeToProof converts a ProofCode to Proof
func CodeToProof(p *ProofCode) *Proof {
	z := new(Proof)
	z.Commitment = p.Commitment
	z.Z1 = new(BigInt.Nat).UnmarshalNat(p.Z1)
	z.Z2 = new(BigInt.Nat).UnmarshalNat(p.Z2)
	z.Z3 = new(BigInt.Nat).UnmarshalNat(p.Z3)
	z.Z4 = new(BigInt.Nat).UnmarshalNat(p.Z4)
	z.W = new(BigInt.Nat).UnmarshalNat(p.W)
	z.Wx = new(BigInt.Nat).UnmarshalNat(p.Wx)
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
	proofcode := &ProofCode{}
	//proofcode := EmptyCode(group)
	cbor.Unmarshal(p.Malbuf, proofcode)
	proof := CodeToProof(proofcode)
	return proof.Verify(group, hash, public)
}
