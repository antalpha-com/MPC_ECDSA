package zkencelg

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
	// C = Enc(x;ρ)
	C *paillier.Ciphertext

	// A = a⋅G
	A curve.Point
	// B = b⋅G
	B curve.Point
	// X = (ab+x)⋅G
	X curve.Point

	Prover *paillier.PublicKey
	Aux    *pedersen.Parameters
}
type Private struct {
	// X = x = Dec(C)
	X *BigInt.Nat

	// Rho = ρ = Nonce(C)
	Rho *BigInt.Nat

	// A = a
	A curve.Scalar
	// B = b
	B curve.Scalar
}

type Commitment struct {
	// S = sˣtᵘ
	S *BigInt.Nat
	// D = Enc(α, r)
	D *paillier.Ciphertext
	// Y = β⋅A+α⋅G
	Y curve.Point
	// Z = β⋅G
	Z curve.Point
	// C = sᵃtᵍ
	T *BigInt.Nat
}

type Proof struct {
	group curve.Curve
	*Commitment
	// Z1 = z₁ = α + ex
	Z1 *BigInt.Nat
	// W = w = β + eb (mod q)
	W curve.Scalar
	// Z2 = z₂ = r⋅ρᵉ (mod N₀)
	Z2 *BigInt.Nat
	// Z3 = z₃ = γ + eμ
	Z3 *BigInt.Nat
}

// ProofCode is used in Cbor, composed of Natcode instead of Nat
// The purpose is to preserve the sign of Nat
type ProofCode struct {
	group curve.Curve
	*Commitment
	// Z1 = z₁ = α + ex
	Z1 *BigInt.NatCode
	// W = w = β + eb (mod q)
	W curve.Scalar
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
	if !public.Prover.ValidateCiphertexts(p.D) {
		return false
	}
	if p.W.IsZero() || p.Y.IsIdentity() || p.Z.IsIdentity() {
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
//		w = e•b+β
func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N()
	NModulus := public.Prover.Modulus()

	alpha := sample.IntervalLEps(rand.Reader)
	alphaScalar := group.NewScalar().SetNat(alpha.Mod1(group.Order()))
	mu := sample.IntervalLN(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)
	beta := sample.Scalar(rand.Reader, group)
	gamma := sample.IntervalLEpsN(rand.Reader)

	commitment := &Commitment{
		S: public.Aux.Commit(private.X, mu),
		D: public.Prover.EncWithNonce(alpha, r),
		Y: beta.Act(public.A).Add(alphaScalar.ActOnBase()),
		Z: beta.ActOnBase(),
		T: public.Aux.Commit(alpha, gamma),
	}

	e, _ := challenge(hash, group, public, commitment)

	// z1 = e•x+α
	z1 := new(BigInt.Nat).SetNat(private.X)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)

	// w = e•b+β
	e1 := new(BigInt.Nat).SetNat(e)
	w := group.NewScalar().SetNat(e1.Mod(e1, group.Order())).Mul(private.B).Add(beta)
	//w := group.NewScalar().SetNat(e.Mod(e, group.Order())).Mul(private.B).Add(beta)

	// z2 = ρ⋅rᵉ
	z2 := new(BigInt.Nat).ExpI(private.Rho, e, NModulus)
	z2.ModMul(z2, r, N)

	// z3 = e•μ+γ
	z3 := new(BigInt.Nat).Mul(e, mu, -1)
	z3.Add(z3, gamma, -1)

	return &Proof{
		group:      group,
		Commitment: commitment,
		Z1:         z1,
		W:          w,
		Z2:         z2,
		Z3:         z3,
	}
}

// Verify checks a Proof is verified
func (p Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	prover := public.Prover

	if !BigInt.IsInIntervalLEps(p.Z1) {
		return false
	}

	e, err := challenge(hash, p.group, public, p.Commitment)
	if err != nil {
		return false
	}

	group := p.group
	q := group.Order()
	eScalar := group.NewScalar().SetNat(e.Mod1(q))

	{
		lhs := prover.EncWithNonce(p.Z1, p.Z2)                  // lhs = Enc(z₁;z₂)
		rhs := public.C.Clone().Mul(prover, e).Add(prover, p.D) // rhs = (e ⊙ C) ⊕ D
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		z1 := group.NewScalar().SetNat(p.Z1.Mod1(q))
		lhs := z1.ActOnBase().Add(p.W.Act(public.A)) // lhs = w⋅A+z₁⋅G
		rhs := eScalar.Act(public.X).Add(p.Y)        // rhs = Y+e⋅X
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		lhs := p.W.ActOnBase()                // lhs = w⋅G
		rhs := eScalar.Act(public.B).Add(p.Z) // rhs = Z+e⋅B
		if !lhs.Equal(rhs) {
			return false
		}
	}

	if !public.Aux.Verify(p.Z1, p.Z3, e, p.T, p.S) {
		return false
	}

	return true
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e *BigInt.Nat, err error) {
	err = hash.WriteAny(public.Aux, public.Prover, public.C, public.A, public.B, public.X,
		commitment.S, commitment.D, commitment.Y, commitment.Z, commitment.T)
	e = sample.IntervalScalar(hash.Digest(), group)
	return
}

// Empty constructs a Proof with empty content
func Empty(group curve.Curve) *Proof {
	return &Proof{
		group: group,
		Commitment: &Commitment{
			Y: group.NewPoint(),
			Z: group.NewPoint(),
		},
		W: group.NewScalar(),
	}
}

// EmptyCode constructs a ProofCode with empty content
func EmptyCode(group curve.Curve) *ProofCode {
	return &ProofCode{
		group: group,
		Commitment: &Commitment{
			Y: group.NewPoint(),
			Z: group.NewPoint(),
		},
		W: group.NewScalar(),
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
	z.W = p.W
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
	z.W = p.W

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
