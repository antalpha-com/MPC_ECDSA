// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package gmp_paillier

import (
	"errors"
	"fmt"
	"io"

	"MPC_ECDSA/internal/params"
	"MPC_ECDSA/pkg/BigInt"
)

var (
	ErrPaillierLength = errors.New("wrong number bit length of Paillier modulus N")
	ErrPaillierEven   = errors.New("modulus N is even")
	ErrPaillierNil    = errors.New("modulus N is nil")
)

// PublicKey is a Paillier public key. It is represented by a modulus N.
type PublicKey struct {
	// n = p⋅q
	n *BigInt.Nat
	// nSquared = n²
	nSquared *BigInt.Nat

	// These values are cached out of convenience, and performance
	nCache *BigInt.Nat
	// nPlusOne = n + 1
	nPlusOne *BigInt.Nat
}

// N is the public modulus making up this key.
func (pk *PublicKey) N() *BigInt.Nat {
	return pk.n
}

// NewPublicKey returns an initialized paillier.PublicKey and caches N, N² and (N-1)/2.
func NewPublicKeyFromN(n *BigInt.Nat) *PublicKey {
	oneNat := new(BigInt.Nat).SetUint64(1)
	nCache := new(BigInt.Nat).SetUint64(0)
	nSquared := new(BigInt.Nat).Mul(n, n, -1)
	nPlusOne := new(BigInt.Nat).Add(n, oneNat, -1)

	return &PublicKey{
		n:        n,
		nSquared: nSquared,
		nCache:   nCache,
		nPlusOne: nPlusOne,
	}
}

// ValidateN performs basic checks to make sure the modulus is valid:
// - log₂(n) = params.BitsPaillier.
// - n is odd.
func ValidateN(n *BigInt.Nat) error {
	if n == nil {
		return ErrPaillierNil
	}
	// log₂(N) = BitsPaillier
	if bits := n.BitLen(); bits != params.BitsPaillier {
		return fmt.Errorf("have: %d, need %d: %w", bits, params.BitsPaillier, ErrPaillierLength)
	}
	if n.Bit(0) != 1 {
		return ErrPaillierEven
	}
	return nil
}

// Enc returns the encryption of m under the public key pk.
// The nonce used to encrypt is returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise.
//
// ct = (1+N)ᵐρᴺ (mod N²).
func (pk PublicKey) Enc(m *BigInt.Nat) (*Ciphertext, *BigInt.Nat) {
	//nonce := sample.UnitModN(rand.Reader, pk.n)
	nonce := new(BigInt.Nat).SetUint64(0x1122)
	return pk.EncWithNonce(m, nonce), nonce
}

// EncWithNonce returns the encryption of m under the public key pk.
// The nonce is not returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise
//
// ct = (1+N)ᵐρᴺ (mod N²).
// a^f(n) * a^-m = a^(f(n)-m) = a^-m  mod n
func (pk PublicKey) EncWithNonce(m *BigInt.Nat, nonce *BigInt.Nat) *Ciphertext {

	mAbs := m.Abs()

	nHalf := new(BigInt.Nat).SetUint64(0)
	nHalf.SetNat(pk.n)
	nHalf.Rsh(nHalf, 1, -1)
	if gt := mAbs.Cmp(nHalf); gt == 1 {
		panic("paillier.Encrypt: tried to encrypt message outside of range [-(N-1)/2, …, (N-1)/2]")
	}
	// (N+1)ᵐ mod N²
	c := new(BigInt.Nat).ExpI(pk.nPlusOne, m, pk.nSquared)
	// ρᴺ mod N²
	// rhoN := pk.nSquared.Exp(nonce, pk.n, pk.nSquared)
	rhoN := new(BigInt.Nat).SetUint64(111)
	rhoN = rhoN.Exp(nonce, pk.n, pk.nSquared)
	// (N+1)ᵐ rho ^ N
	out := new(BigInt.Nat).ModMul(c, rhoN, pk.nSquared)
	return &Ciphertext{c: out}
}

// Equal returns true if pk ≡ other.
func (pk PublicKey) Equal(other *PublicKey) bool {
	eq := (pk.n).Cmp(other.n)
	return eq == 0
}

// ValidateCiphertexts checks if all ciphertexts are in the correct range and coprime to N²
// ct ∈ [1, …, N²-1] AND GCD(ct,N²) = 1.
func (pk PublicKey) ValidateCiphertexts(cts ...*Ciphertext) bool {
	for _, ct := range cts {
		if ct == nil {
			return false
		}
		// lt := NatToGmpInt(ct.c).Cmp(NatToGmpInt(pk.nSquared.Modulus.Nat()))
		lt := ct.c.CmpMod(pk.nSquared)
		if lt == 1 {
			return false
		}
		if ct.c.IsUnit(pk.nSquared) != 1 {
			return false
		}
	}
	return true
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (pk *PublicKey) WriteTo(w io.Writer) (int64, error) {
	if pk == nil {
		return 0, io.ErrUnexpectedEOF
	}
	buf := pk.n.Bytes()
	n, err := w.Write(buf)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (PublicKey) Domain() string {
	return "Paillier PublicKey"
}

// Modulus returns an arith.Modulus for N which may allow for accelerated exponentiation when this
// public key was generated from a secret key.
func (pk *PublicKey) Modulus() *BigInt.Nat {
	return pk.n
}

// ModulusSquared returns an arith.Modulus for N² which may allow for accelerated exponentiation when this
// public key was generated from a secret key.
func (pk *PublicKey) ModulusSquared() *BigInt.Nat {
	return pk.nSquared
}
