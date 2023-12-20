package zkprm

import (
	"crypto/rand"
	"github.com/fxamacker/cbor/v2"
	"io"

	"MPC_ECDSA/internal/params"
	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/pedersen"
	"MPC_ECDSA/pkg/pool"
)

type Public struct {
	N    *BigInt.Nat
	S, T *BigInt.Nat
}
type Private struct {
	Lambda, Phi, P, Q *BigInt.Nat
}

type Proof struct {
	As, Zs [params.StatParam]*BigInt.Nat
}

// ProofCode is used in Cbor, composed of Natcode instead of Nat
// The purpose is to preserve the sign of Nat
type ProofCode struct {
	As, Zs [params.StatParam]*BigInt.NatCode
}

// Proofbuf is used to store the byte stream during communication
type Proofbuf struct {
	Malbuf []byte
}

func ProofToCode(p *Proof) *ProofCode {
	z := new(ProofCode)
	for i, value := range p.As {
		z.As[i] = value.MarshalNat()
	}
	for i, value := range p.Zs {
		z.Zs[i] = value.MarshalNat()
	}
	return z
}
func CodeToProof(p *ProofCode) *Proof {
	z := new(Proof)
	for i, value := range p.As {
		z.As[i] = new(BigInt.Nat).UnmarshalNat(value)
	}
	for i, value := range p.Zs {
		z.Zs[i] = new(BigInt.Nat).UnmarshalNat(value)
	}
	return z
}

// IsValid checks whether a Proof is valid
func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if !BigInt.IsValidBigModN(public.N, append(p.As[:], p.Zs[:]...)...) {
		return false
	}
	return true
}

// NewProof generates a proof that:
// s = t^lambda (mod N).
func NewProof(private Private, hash *hash.Hash, public Public, pl *pool.Pool) *Proof {
	lambda := private.Lambda
	phi := new(BigInt.Nat).SetNat(private.Phi)
	n := public.N
	var (
		as [params.StatParam]*BigInt.Nat
		As [params.StatParam]*BigInt.Nat
	)
	lockedRand := pool.NewLockedReader(rand.Reader)
	pl.Parallelize(params.StatParam, func(i int) interface{} {
		// aᵢ ∈ mod ϕ(N)
		as[i] = sample.ModN(lockedRand, phi)
		// Aᵢ = tᵃ mod N
		As[i] = As[i].Exp(public.T, as[i], n)

		return nil
	})

	es, _ := challenge(hash, public, As)
	// Modular addition is not expensive enough to warrant parallelizing
	var Zs [params.StatParam]*BigInt.Nat
	for i := 0; i < params.StatParam; i++ {
		z := as[i]
		// The challenge is public, so branching is ok
		if es[i] {
			tmp := new(BigInt.Nat).SetUint64(0)
			tmp.ModAdd(z, lambda, phi)
			z.SetNat(tmp)
		}
		Zs[i] = z
	}

	return &Proof{
		As: As,
		Zs: Zs,
	}
}

// Verify checks a Proof is verified
func (p *Proof) Verify(public Public, hash *hash.Hash, pl *pool.Pool) bool {
	if p == nil {
		return false
	}
	if err := pedersen.ValidateParameters(public.N, public.S, public.T); err != nil {
		return false
	}

	n, s, t := public.N, public.S, public.T

	es, err := challenge(hash, public, p.As)
	if err != nil {
		return false
	}

	one := new(BigInt.Nat).SetUint64(1)
	verifications := pl.Parallelize(params.StatParam, func(i int) interface{} {
		lhs := new(BigInt.Nat).SetUint64(0)
		rhs := new(BigInt.Nat).SetUint64(0)
		z := p.Zs[i]
		a := p.As[i]

		if !BigInt.IsValidBigModN(n, a, z) {
			return false
		}

		if a.Cmp(one) == 0 {
			return false
		}

		lhs.Exp(t, z, n)
		if es[i] {
			rhs.Mul(a, s, -1)
			rhs.Mod(rhs, n)
		} else {
			rhs.SetNat(a)
		}

		if lhs.Cmp(rhs) != 0 {
			return false
		}

		return true
	})
	for i := 0; i < len(verifications); i++ {
		ok, _ := verifications[i].(bool)
		if !ok {
			return false
		}
	}
	return true
}

func challenge(hash *hash.Hash, public Public, A [params.StatParam]*BigInt.Nat) (es []bool, err error) {
	err = hash.WriteAny(public.N, public.S, public.T)
	for _, a := range A {
		_ = hash.WriteAny(a)
	}

	tmpBytes := make([]byte, params.StatParam)
	_, _ = io.ReadFull(hash.Digest(), tmpBytes)

	es = make([]bool, params.StatParam)
	for i := range es {
		b := (tmpBytes[i] & 1) == 1
		es[i] = b
	}

	return
}

// NewProofMal generates a new Proof and Marshal it, return the Proofbuf
func NewProofMal(private Private, hash *hash.Hash, public Public, pl *pool.Pool) *Proofbuf {
	proof := NewProof(private, hash, public, pl)
	proofcode := ProofToCode(proof)
	buf, _ := cbor.Marshal(proofcode)
	proofbuf := new(Proofbuf)
	proofbuf.Malbuf = buf //
	//var a []byte
	//var b []byte
	//a = b
	return proofbuf
}

// VerifyMal can verify a Proof in Proofbuf Type
func (p *Proofbuf) VerifyMal(public Public, hash *hash.Hash, pl *pool.Pool) bool {
	proofcode := &ProofCode{}
	//proofcode := EmptyCode(group)
	cbor.Unmarshal(p.Malbuf, proofcode)
	proof := CodeToProof(proofcode)
	return proof.Verify(public, hash, pl)
}
