package zkmul

import (
	"crypto/rand"
	"github.com/fxamacker/cbor/v2"

	"MPC_ECDSA/pkg/BigInt"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"
)

type Public struct {
	// X = Enc(x; ρₓ)
	X *paillier.Ciphertext

	// Y is a ciphertext over the prover's public key
	Y *paillier.Ciphertext

	// C = x ⊙ Y % ρ
	C *paillier.Ciphertext

	// Prover = N
	Prover *paillier.PublicKey
}

type Private struct {
	// X = x is the plaintext of Public.X.
	X *BigInt.Nat

	// Rho = ρ is the nonce for Public.C.
	Rho *BigInt.Nat

	// RhoX = ρₓ is the nonce for Public.X
	RhoX *BigInt.Nat
}

type Commitment struct {
	// A = α ⊙ Y % ρ
	A *paillier.Ciphertext
	// B = Enc(α;s)
	B *paillier.Ciphertext
}

type Proof struct {
	*Commitment
	// Z = α + ex
	Z *BigInt.Nat
	// U = r⋅ρᵉ mod N
	U *BigInt.Nat
	// V = s⋅ρₓᵉ
	V *BigInt.Nat
}

// ProofCode is used in Cbor, composed of Natcode instead of Nat
// The purpose is to preserve the sign of Nat
type ProofCode struct {
	*Commitment
	// Z = α + ex
	Z *BigInt.NatCode
	// U = r⋅ρᵉ mod N
	U *BigInt.NatCode
	// V = s⋅ρₓᵉ
	V *BigInt.NatCode
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
	if !BigInt.IsValidNatModN(public.Prover.N(), p.U, p.V) {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.A, p.B) {
		return false
	}
	return true
}

// NewProof generates a proof that:
//   - X = x⋅G
//   - B = Enc₀(α,ρ)
//
// With:
//   - Z = α + ex
//   - U = r⋅ρᵉ mod N
//   - V = s⋅ρₓᵉ mod N
func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N()
	NModulus := public.Prover.Modulus()

	prover := public.Prover

	alpha := sample.IntervalLEps(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)
	s := sample.UnitModN(rand.Reader, N)

	A := public.Y.Clone().Mul(prover, alpha)
	A.Randomize(prover, r)

	commitment := &Commitment{
		A: A,
		B: prover.EncWithNonce(alpha, s),
	}
	e, _ := challenge(hash, group, public, commitment)

	// Z = α + ex
	z := new(BigInt.Nat).SetNat(private.X)
	z.Mul(e, z, -1)
	z.Add(z, alpha, -1)
	// U = r⋅ρᵉ mod N
	u := new(BigInt.Nat).ExpI(private.Rho, e, NModulus)
	u.ModMul(u, r, N)
	// V = s⋅ρₓᵉ mod N
	v := new(BigInt.Nat).ExpI(private.RhoX, e, NModulus)
	v.ModMul(v, s, N)

	return &Proof{
		Commitment: commitment,
		Z:          z,
		U:          u,
		V:          v,
	}
}

// Verify checks a Proof is verified
func (p *Proof) Verify(group curve.Curve, hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	prover := public.Prover

	e, err := challenge(hash, group, public, p.Commitment)
	if err != nil {
		return false
	}

	{
		// lhs = (z ⊙ Y)•uᴺ
		lhs := public.Y.Clone().Mul(prover, p.Z)
		lhs.Randomize(prover, p.U)

		// (e ⊙ C) ⊕ A
		rhs := public.C.Clone().Mul(prover, e).Add(prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = Enc(z;v)
		lhs := prover.EncWithNonce(p.Z, p.V)

		// rhs = (e ⊙ X) ⊕ B
		rhs := public.X.Clone().Mul(prover, e).Add(prover, p.B)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e *BigInt.Nat, err error) {
	err = hash.WriteAny(public.Prover,
		public.X, public.Y, public.C,
		commitment.A, commitment.B)
	e = sample.IntervalScalar(hash.Digest(), group)
	return
}

// ProofToCode converts a Proof to a ProofCode
func ProofToCode(p *Proof) *ProofCode {
	z := new(ProofCode)
	z.Commitment = p.Commitment
	z.Z = p.Z.MarshalNat()
	z.U = p.U.MarshalNat()
	z.V = p.V.MarshalNat()
	return z
}

// CodeToProof converts a ProofCode to Proof
func CodeToProof(p *ProofCode) *Proof {
	z := new(Proof)
	z.Commitment = p.Commitment
	z.Z = new(BigInt.Nat).UnmarshalNat(p.Z)
	z.U = new(BigInt.Nat).UnmarshalNat(p.U)
	z.V = new(BigInt.Nat).UnmarshalNat(p.V)
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
	// proof := Empty(group)
	cbor.Unmarshal(p.Malbuf, proofcode)
	proof := CodeToProof(proofcode)
	return proof.Verify(group, hash, public)
}
