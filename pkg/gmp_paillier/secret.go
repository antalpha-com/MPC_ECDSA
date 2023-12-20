// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package gmp_paillier

import (
	"crypto/rand"
	"errors"
	"fmt"

	"MPC_ECDSA/internal/params"
	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/pedersen"
	"MPC_ECDSA/pkg/pool"
)

var (
	ErrPrimeBadLength = errors.New("prime factor is not the right length")
	ErrNotBlum        = errors.New("prime factor is not equivalent to 3 (mod 4)")
	ErrNotSafePrime   = errors.New("supposed prime factor is not a safe prime")
	ErrPrimeNil       = errors.New("prime is nil")
)

// SecretKey is the secret key corresponding to a Public Paillier Key.
//
// A public key is a modulus N, and the secret key contains the information
// needed to factor N into two primes, P and Q. This allows us to decrypt
// values encrypted using this modulus.
type SecretKey struct {
	*PublicKey
	// p, q such that N = p⋅q
	p, q *BigInt.Nat
	// phi = ϕ = (p-1)(q-1)
	phi *BigInt.Nat
	// phiInv = ϕ⁻¹ mod N
	phiInv *BigInt.Nat
	//if CRT==1，else CRT==0
	crt int
	//pSquared=p^2,qSquared=q^2
	psquared, qsquared *BigInt.Nat
	pinv, pinvsquared  *BigInt.Nat
}

// P returns the first of the two factors composing this key.
func (sk *SecretKey) P() *BigInt.Nat {
	return sk.p
}

// Q returns the second of the two factors composing this key.
func (sk *SecretKey) Q() *BigInt.Nat {
	return sk.q
}

// P returns the first of the two factors composing this key.
func (sk *SecretKey) Psquared() *BigInt.Nat {
	return sk.psquared
}

// Q returns the second of the two factors composing this key.
func (sk *SecretKey) Qsquared() *BigInt.Nat {
	return sk.qsquared
}

// Phi returns ϕ = (P-1)(Q-1).
//
// This is the result of the totient function ϕ(N), where N = P⋅Q
// is our public key. This function counts the number of units mod N.
//
// This quantity is useful in ZK proofs.
func (sk *SecretKey) Phi() *BigInt.Nat {
	return sk.phi
}

// KeyGen generates a new PublicKey and it's associated SecretKey.
func KeyGen(pl *pool.Pool) (pk *PublicKey, sk *SecretKey) {
	sk = NewSecretKey(pl)
	pk = sk.PublicKey
	return
}

// NewSecretKey generates primes p and q suitable for the scheme, and returns the initialized SecretKey.
func NewSecretKey(pl *pool.Pool) *SecretKey {
	// TODO maybe we could take the reader as argument?
	return NewSecretKeyFromPrimes(sample.Paillier(rand.Reader, pl))
}

// NewSecretKeyFromPrimes generates a new SecretKey. Assumes that P and Q are prime.
func NewSecretKeyFromPrimes(P, Q *BigInt.Nat) *SecretKey {
	oneInt := new(BigInt.Nat).SetUint64(1)
	n := new(BigInt.Nat).Mul(P, Q, -1)
	nPlusOne := new(BigInt.Nat).Add(n, oneInt, -1)
	pMinus1 := new(BigInt.Nat).Sub(P, oneInt, -1)
	qMinus1 := new(BigInt.Nat).Sub(Q, oneInt, -1)
	phi := new(BigInt.Nat).Mul(pMinus1, qMinus1, -1)
	// ϕ⁻¹ mod N
	phiInv := new(BigInt.Nat).ModInverse(phi, n)

	pInv := new(BigInt.Nat).ModInverse(P, Q)

	pSquared := new(BigInt.Nat).Mul(P, P, -1)
	qSquared := new(BigInt.Nat).Mul(Q, Q, -1)
	nSquared := new(BigInt.Nat).Mul(n, n, -1)
	pInvSquared := new(BigInt.Nat).ModInverse(pSquared, qSquared)

	return &SecretKey{
		p:           P,
		q:           Q,
		phi:         phi,
		phiInv:      phiInv,
		crt:         1,
		psquared:    pSquared,
		qsquared:    qSquared,
		pinv:        pInv,
		pinvsquared: pInvSquared,

		PublicKey: &PublicKey{
			n:        n,
			nSquared: nSquared,
			nCache:   n,
			nPlusOne: nPlusOne,
		},
	}
}

// Dec decrypts c and returns the plaintext m ∈ ± (N-2)/2.
// It returns an error if gcd(c, N²) != 1 or if c is not in [1, N²-1].
func (sk *SecretKey) Dec(ct *Ciphertext) (*BigInt.Nat, error) {
	oneNat := new(BigInt.Nat).SetUint64(1)
	n := sk.PublicKey.n

	if !sk.PublicKey.ValidateCiphertexts(ct) {
		return nil, errors.New("paillier: failed to decrypt invalid ciphertext")
	}
	phi := sk.phi
	phiInv := sk.phiInv

	// r = c^Phi 						(mod N²)
	//result1 := new(BigInt.Nat).Exp(ct.c, phi, sk.PublicKey.nSquared)
	result := sk.CRTExpN2(ct.c, phi) //CRTG

	// r = c^Phi - 1
	result.Sub(result, oneNat, -1)

	// r = [(c^Phi - 1)/N]
	result.Div(result, n)

	// r = [(c^Phi - 1)/N] • Phi^-1		(mod N)
	result.ModMul(result, phiInv, n)

	// see 6.1 https://www.iacr.org/archive/crypto2001/21390136.pdf
	//result2 := new(BigInt.Nat).SetUint64(0)
	return new(BigInt.Nat).SetModSymmetric(result, n), nil
	// return result, nil
}
func (sk *SecretKey) CRTExpN2(m *BigInt.Nat, e *BigInt.Nat) *BigInt.Nat {
	c1 := new(BigInt.Nat).SetUint64(0)
	//func (z *Nat) CRTExpN2(x, e, n2, p2, q2, p, q, pinv2 *Nat) *Nat {
	c1.CRTExpN2(m, e, sk.nSquared, sk.psquared, sk.qsquared, sk.p, sk.q, sk.pinvsquared)
	return c1
}
func (sk *SecretKey) CRTExpN(m *BigInt.Nat, e *BigInt.Nat) *BigInt.Nat {
	c1 := new(BigInt.Nat).SetUint64(0)
	c1.CRTExpN(m, e, sk.n, sk.p, sk.q, sk.pinv)
	return c1
}

// DecWithRandomness returns the underlying plaintext, as well as the randomness used.
func (sk *SecretKey) DecWithRandomness(ct *Ciphertext) (*BigInt.Nat, *BigInt.Nat, error) {
	m, err := sk.Dec(ct)
	if err != nil {
		return nil, nil, err
	}

	mNeg := new(BigInt.Nat).SetNat(m)
	mNeg.SetSign(1)
	// mNeg := new(BigInt.Int).SetInt(m).Neg(1)

	// x = C(N+1)⁻ᵐ (mod N)
	x := new(BigInt.Nat).ExpI(sk.PublicKey.nPlusOne, mNeg, sk.PublicKey.n)
	// xGmpInt := NatToGmpInt(x).ModMul(NatToGmpInt(x), NatToGmpInt(ct.c), NatToGmpInt(sk.n.Modulus.Nat()))
	x.ModMul(x, ct.c, sk.PublicKey.n)

	// r = xⁿ⁻¹ (mod N)
	// nInverse := new(GmpInt).ModInverse(NatToGmpInt(sk.nNat), NatToGmpInt((sk.Phi())))
	nInverse := new(BigInt.Nat).ModInverse(sk.PublicKey.nCache, sk.phi)
	r := new(BigInt.Nat).Exp(x, nInverse, sk.PublicKey.n)

	return m, r, nil
}

func (sk SecretKey) GeneratePedersen() (*pedersen.Parameters, *BigInt.Nat) {
	s, t, lambda := sample.Pedersen(rand.Reader, sk.phi, sk.PublicKey.n)
	ped := pedersen.New(sk.PublicKey.n, s, t)
	return ped, lambda
}

// ValidatePrime checks whether p is a suitable prime for Paillier.
// Checks:
// - log₂(p) ≡ params.BitsBlumPrime.
// - p ≡ 3 (mod 4).
// - q := (p-1)/2 is prime.
func ValidatePrime(p *BigInt.Nat) error {
	if p == nil {
		return ErrPrimeNil
	}
	// check bit lengths
	const bitsWant = params.BitsBlumPrime
	// Technically, this leaks the number of bits, but this is fine, since returning
	// an error asserts this number statically, anyways.
	if bits := p.BitLen(); bits != bitsWant {
		return fmt.Errorf("invalid prime size: have: %d, need %d: %w", bits, bitsWant, ErrPrimeBadLength)
	}
	// check == 3 (mod 4)
	if p.Byte(0)&0b11 != 3 {
		return ErrNotBlum
	}

	// check (p-1)/2 is prime
	pMinus1Div2 := new(BigInt.Nat).Rsh(p, 1, -1)

	if !pMinus1Div2.ProbablyPrime(1) {
		return ErrNotSafePrime
	}
	return nil
}

// Exp is equivalent to (BigInt.Nat).Exp(x, e, n.Modulus).
// It returns xᵉ (mod n).
func CRTExp(x, e, n, p, q, u *BigInt.Nat) *BigInt.Nat {

	xp := new(BigInt.Nat).SetUint64(0)
	xq := new(BigInt.Nat).SetUint64(0)

	//ep:=new(BigInt.Nat).SetUint64(0)
	//eq:=new(BigInt.Nat).SetUint64(0)
	xp.Mod(x, p)
	xq.Mod(x, q)

	//ep.Mod(e,)
	//ep=e mod fai(p),ep=e mod fai(p) is better

	xp.Exp(xp, e, p) // x₁ = xᵉ (mod p₁)
	xq.Exp(xq, e, q) // x₂ = xᵉ (mod p₂)
	// r = x₁ + p₁ ⋅ [p₁⁻¹ (mod p₂)] ⋅ [x₁ - x₂] (mod n)
	r := new(BigInt.Nat).SetUint64(0)
	r = xq.ModSub(xq, xp, n)
	r.ModMul(r, u, n)
	r.ModMul(r, p, n)
	r.ModAdd(r, xp, n)
	return r
}
