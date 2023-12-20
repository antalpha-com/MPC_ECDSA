package zkmulstar

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
	// C = Enc₀(?;?)
	C *paillier.Ciphertext

	// D = (x ⨀ C) ⨁ Enc₀(y;ρ)
	D *paillier.Ciphertext

	// X = gˣ
	X curve.Point

	// Verifier = N₀
	Verifier *paillier.PublicKey
	Aux      *pedersen.Parameters
}

type Private struct {
	// X ∈ ± 2ˡ
	X *BigInt.Nat

	// Rho = ρ = Nonce D
	Rho *BigInt.Nat
}

type Commitment struct {
	// A = (α ⊙ c) ⊕ Enc(N₀, β, r)
	A *paillier.Ciphertext
	// Bₓ = gᵃ
	Bx curve.Point
	// E = sᵃ tᵍ
	E *BigInt.Nat
	// S = sˣ tᵐ
	S *BigInt.Nat
}

type Proof struct {
	group curve.Curve
	*Commitment
	// Z1 = α + ex
	Z1 *BigInt.Nat
	// Z2 = y + em
	Z2 *BigInt.Nat
	// W = ρᵉ•r mod N₀
	W *BigInt.Nat
}

// ProofCode is used in Cbor, composed of Natcode instead of Nat
// The purpose is to preserve the sign of Nat
type ProofCode struct {
	group curve.Curve
	*Commitment
	// Z1 = α + ex
	Z1 *BigInt.NatCode
	// Z2 = y + em
	Z2 *BigInt.NatCode
	// W = ρᵉ•r mod N₀
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
	if !BigInt.IsValidNatModN(public.Verifier.N(), p.W) {
		return false
	}
	if !public.Verifier.ValidateCiphertexts(p.A) {
		return false
	}
	if p.Bx.IsIdentity() {
		return false
	}
	return true
}

// NewProof generates a proof that:
//   - X = x⋅G
//   - B = Enc₀(α,ρ)
//
// With:
//   - z₁ = e•x+α
//   - z₂ = e•m+γ
//   - w = ρᵉ•r mod N₀
func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	N0 := public.Verifier.N()
	N0Modulus := public.Verifier.Modulus()

	verifier := public.Verifier

	alpha := sample.IntervalLEps(rand.Reader)

	r := sample.UnitModN(rand.Reader, N0)

	gamma := sample.IntervalLEpsN(rand.Reader)
	m := sample.IntervalLEpsN(rand.Reader)

	A := public.C.Clone().Mul(verifier, alpha)
	A.Randomize(verifier, r)

	commitment := &Commitment{
		A:  A,
		Bx: group.NewScalar().SetNat(alpha.Mod1(group.Order())).ActOnBase(),
		E:  public.Aux.Commit(alpha, gamma),
		S:  public.Aux.Commit(private.X, m),
	}

	e, _ := challenge(group, hash, public, commitment)

	// z₁ = e•x+α
	z1 := new(BigInt.Nat).SetNat(private.X)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)
	// z₂ = e•m+γ
	z2 := new(BigInt.Nat).Mul(e, m, -1)
	z2.Add(z2, gamma, -1)
	// w = ρᵉ•r mod N₀
	w := new(BigInt.Nat).ExpI(private.Rho, e, N0Modulus)
	w.ModMul(w, r, N0)

	return &Proof{
		group:      group,
		Commitment: commitment,
		Z1:         z1,
		Z2:         z2,
		W:          w,
	}
}

// Verify checks a Proof is verified
func (p *Proof) Verify(group curve.Curve, hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	verifier := public.Verifier

	if !BigInt.IsInIntervalLEps(p.Z1) {
		return false
	}

	e, err := challenge(group, hash, public, p.Commitment)
	if err != nil {
		return false
	}

	if !public.Aux.Verify(p.Z1, p.Z2, e, p.E, p.S) {
		return false
	}

	{
		// lhs = z₁ ⊙ C + rand
		lhs := public.C.Clone().Mul(verifier, p.Z1)
		lhs.Randomize(verifier, p.W)

		// rhsCt = A ⊕ (e ⊙ D)
		rhs := public.D.Clone().Mul(verifier, e).Add(verifier, p.A)

		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = [z₁]G
		lhs := p.group.NewScalar().SetNat(p.Z1.Mod1(p.group.Order())).ActOnBase()

		// rhs = [e]X + Bₓ
		rhs := p.group.NewScalar().SetNat(e.Mod1(p.group.Order())).Act(public.X)
		rhs = rhs.Add(p.Bx)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(group curve.Curve, hash *hash.Hash, public Public, commitment *Commitment) (e *BigInt.Nat, err error) {
	err = hash.WriteAny(public.Aux, public.Verifier,
		public.C, public.D, public.X,
		commitment.A, commitment.Bx,
		commitment.E, commitment.S)
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
	// proofcode := &ProofCode{}
	proofcode := EmptyCode(group)
	cbor.Unmarshal(p.Malbuf, proofcode)
	proof := CodeToProof(proofcode)
	return proof.Verify(group, hash, public)
}
