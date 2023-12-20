package arith

import (
	"MPC_ECDSA/pkg/BigInt"
)

// Modulus wraps a BigInt.Modulus and enables faster modular exponentiation when
// the factorization is known.
// When n = p⋅q, xᵉ (mod n) can be computed with only two exponentiations
// with p and q respectively.
type Modulus struct {
	// represents modulus n
	n *BigInt.Nat
	// n = p⋅q
	p, q *BigInt.Nat
	// pInv = p⁻¹ (mod q)
	pNat, pInv *BigInt.Nat
}

// GetN return the n of Modulus in Nat
func (n *Modulus) GetN() *BigInt.Nat {
	t := new(BigInt.Nat)
	t = n.n
	return t
}

// BitLen return the length of n in Modulus
func (n *Modulus) BitLen() int {
	return n.n.BitLen()
}

// hasFactorization checks whether Modulus is nil
func (n *Modulus) hasFactorization() bool {
	return n.p != nil && n.q != nil && n.pNat != nil && n.pInv != nil
}

// ModulusFromN creates a simple wrapper around a given modulus n.
// The modulus is not copied.
func ModulusFromN(n *BigInt.Nat) *Modulus {
	return &Modulus{
		n: n,
	}
}

// ModulusFromFactors creates the necessary cached values to accelerate
// exponentiation mod n.
func ModulusFromFactors(p, q *BigInt.Nat) *Modulus {
	nNat := new(BigInt.Nat).Mul(p, q, -1)     //n=p*q
	pInvQ := new(BigInt.Nat).ModInverse(p, q) //p^(-1)=p^(-1)%q
	pNat := new(BigInt.Nat).SetNat(p)         //p
	return &Modulus{
		n:    nNat,
		p:    p,
		q:    q,
		pNat: pNat,
		pInv: pInvQ,
	}
}

// Exp is equivalent to (BigInt.Nat).Exp(x, e, n.Modulus).
// It returns xᵉ (mod n) in a new Nat
func (nMod *Modulus) Exp(x, e *BigInt.Nat) *BigInt.Nat {
	if nMod.hasFactorization() {
		var xp, xq BigInt.Nat
		xp.Exp(x, e, nMod.p) // x₁ = xᵉ (mod p₁)
		xq.Exp(x, e, nMod.q) // x₂ = xᵉ (mod p₂)
		// r = x₁ + p₁ ⋅ [p₁⁻¹ (mod p₂)] ⋅ [x₁ - x₂] (mod n)
		r := xq.ModSub(&xq, &xp, nMod.n)
		r.ModMul(r, nMod.pInv, nMod.n)
		r.ModMul(r, nMod.pNat, nMod.n)
		r.ModAdd(r, &xp, nMod.n)
		return r
	}
	return new(BigInt.Nat).Exp(x, e, nMod.n)
}

// ExpI is equivalent to (BigInt.Nat).ExpI(x, e, n.Modulus).
// It returns xᵉ (mod n) in a new Nat
func (nMod *Modulus) ExpI(x *BigInt.Nat, e *BigInt.Nat) *BigInt.Nat {
	if nMod.hasFactorization() {
		y := nMod.Exp(x, e.Abs())
		inverted := new(BigInt.Nat).ModInverse(y, nMod.n)
		//y.CondAssign(e.IsNegative(), inverted)
		return inverted
	}
	return new(BigInt.Nat).ExpI(x, e, nMod.n)
}

// Nat return the n in Modulus in Nat
func (m *Modulus) Nat() *BigInt.Nat {
	return m.n
}

// ModulusFromUint64 sets the Nat according to an integer
func ModulusFromUint64(x uint64) *Modulus {
	z := new(Modulus)
	z.n = new(BigInt.Nat)
	z.n.SetUint64(x)
	return z
}

// ModulusFromBytes creates a new Nat, converting from big endian bytes
//
// This function will remove leading zeros, thus leaking the true size of the Nat.
// See the documentation for the Nat type, for more information about this contract.
func ModulusFromBytes(buf []byte) *Modulus {
	z := new(Modulus)
	z.n = new(BigInt.Nat)
	z.n.SetBytes(buf)
	return z
}

// ModulusFromHex creates a new Nat from a hex string.
//
// The same rules as Nat.SetHex apply.
//
// Additionally, this function will remove leading zeros, leaking the true size of the Nat.
// See the documentation for the Nat type, for more information about this contract.
func ModulusFromHex(hex string) *Modulus {
	z := new(Modulus)
	z.n = new(BigInt.Nat)
	z.n.SetHex(hex)
	return z
}
