package pedersen

import (
	"fmt"
	"io"

	"MPC_ECDSA/internal/params"
	"MPC_ECDSA/pkg/BigInt"
)

type Error string

const (
	ErrNilFields    Error = "contains nil field"
	ErrSEqualT      Error = "S cannot be equal to T"
	ErrNotValidModN Error = "S and T must be in [1,…,N-1] and coprime to N"
)

func (e Error) Error() string {
	return fmt.Sprintf("pedersen: %s", string(e))
}

type Parameters struct {
	n    *BigInt.Nat
	s, t *BigInt.Nat
}

// New returns a new set of Pedersen parameters.
// Assumes ValidateParameters(n, s, t) returns nil.
func New(n *BigInt.Nat, s, t *BigInt.Nat) *Parameters {
	return &Parameters{
		s: s,
		t: t,
		n: n,
	}
}

// ValidateParameters check n, s and t, and returns an error if any of the following is true:
// - n, s, or t is nil.
// - s, t are not in [1, …,n-1].
// - s, t are not coprime to N.
// - s = t.
func ValidateParameters(n *BigInt.Nat, s, t *BigInt.Nat) error {
	if n == nil || s == nil || t == nil {
		return ErrNilFields
	}
	// s, t ∈ ℤₙˣ
	if !BigInt.IsValidNatModN(n, s, t) {
		return ErrNotValidModN
	}
	// s ≡ t
	eq := s.Cmp(t)
	if eq == 0 {
		return ErrSEqualT
	}
	return nil
}

// N = p•q, p ≡ q ≡ 3 mod 4.
func (p Parameters) N() *BigInt.Nat { return p.n }

// S = r² mod N.
func (p Parameters) S() *BigInt.Nat { return p.s }

// T = Sˡ mod N.
func (p Parameters) T() *BigInt.Nat { return p.t }

// Commit computes sˣ tʸ (mod N)
//
// x and y are taken as BigInt.Int, because we want to keep these values in secret,
// in general. The commitment produced, on the other hand, hides their values,
// and can be safely shared.
func (p Parameters) Commit(x, y *BigInt.Nat) *BigInt.Nat {
	sx := new(BigInt.Nat).SetUint64(0)
	ty := new(BigInt.Nat).SetUint64(0)
	result := new(BigInt.Nat).SetUint64(0)
	sx.ExpI(p.s, x, p.n)
	ty.ExpI(p.t, y, p.n)
	result.ModMul(sx, ty, p.n)
	return result
}

// Verify returns true if sᵃ tᵇ ≡ S Tᵉ (mod N).
func (p Parameters) Verify(a, b, e *BigInt.Nat, S, T *BigInt.Nat) bool {
	if a == nil || b == nil || S == nil || T == nil || e == nil {
		return false
	}
	nMod := p.n
	if !BigInt.IsValidNatModN(nMod, S, T) {
		return false
	}

	sa := new(BigInt.Nat).SetUint64(0)
	tb := new(BigInt.Nat).SetUint64(0)
	lhs := new(BigInt.Nat).SetUint64(0)

	sa.ExpI(p.s, a, p.n)     // sᵃ (mod N)
	tb.ExpI(p.t, b, p.n)     // tᵇ (mod N)
	lhs.ModMul(sa, tb, nMod) // lhs = sᵃ⋅tᵇ (mod N)

	te := new(BigInt.Nat).SetUint64(0)
	rhs := new(BigInt.Nat).SetUint64(0)
	te.ExpI(T, e, p.n)      // Tᵉ (mod N)
	rhs.ModMul(te, S, nMod) // rhs = S⋅Tᵉ (mod N)
	return lhs.Eq(rhs) == 1
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (p *Parameters) WriteTo(w io.Writer) (int64, error) {
	if p == nil {
		return 0, io.ErrUnexpectedEOF
	}
	nAll := int64(0)
	buf := make([]byte, params.BytesIntModN)

	// write N, S, T
	for _, i := range []*BigInt.Nat{p.n, p.s, p.t} {
		buf = i.Bytes()
		n, err := w.Write(buf)
		nAll += int64(n)
		if err != nil {
			return nAll, err
		}
	}
	return nAll, nil
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (Parameters) Domain() string {
	return "Pedersen Parameters"
}
