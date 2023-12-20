// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package gmp_paillier

import (
	"MPC_ECDSA/internal/params"
	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/math/sample"
	"crypto/rand"
	"io"
)

// Ciphertext represents an integer of the for (1+N)ᵐρᴺ (mod N²), representing the encryption of m ∈ ℤₙˣ.
type Ciphertext struct {
	c *BigInt.Nat
}

// Add sets ct to the homomorphic sum ct ⊕ ct₂.
// ct ← ct•ct₂ (mod N²).
func (ct *Ciphertext) Add(pk *PublicKey, ct2 *Ciphertext) *Ciphertext {
	if ct2 == nil {
		return ct
	}
	ct3 := new(BigInt.Nat).ModMul(ct.c, ct2.c, pk.nSquared)
	ct.c.SetNat(ct3)
	return ct
}

// Mul sets ct to the homomorphic multiplication of k ⊙ ct.
// ct ← ctᵏ (mod N²).
func (ct *Ciphertext) Mul(pk *PublicKey, k *BigInt.Nat) *Ciphertext {
	if k == nil {
		return ct
	}

	ct2 := new(BigInt.Nat).ExpI(ct.c, k, pk.nSquared)
	ct.c.SetNat(ct2)

	return ct
}

// Equal check whether ct ≡ ctₐ (mod N²).
func (ct *Ciphertext) Equal(ctA *Ciphertext) bool {
	return ct.c.Eq(ctA.c) == 1
}

// Clone returns a deep copy of ct.
func (ct Ciphertext) Clone() *Ciphertext {
	c := new(BigInt.Nat).SetUint64(0)
	c.SetNat(ct.c)
	return &Ciphertext{c: c}
}

// Randomize multiplies the ciphertext's nonce by a newly generated one.
// ct ← ct ⋅ nonceᴺ (mod N²).
// If nonce is nil, a random one is generated.
// The receiver is updated, and the nonce update is returned.
func (ct *Ciphertext) Randomize(pk *PublicKey, nonce *BigInt.Nat) *BigInt.Nat {
	if nonce == nil {
		nonce = sample.UnitModN(rand.Reader, pk.n)
	}
	// c = c*r^N
	//tmp := new(BigInt.Nat).Exp(nonce, pk.nCache, pk.nSquared.Nat())
	tmp := new(BigInt.Nat).Exp(nonce, pk.nCache, pk.nSquared)
	// tmp := pk.nSquared.Exp(nonce, pk.nNat)
	ct2 := new(BigInt.Nat).ModMul(ct.c, tmp, pk.nSquared)
	ct.c.SetNat(ct2)
	return nonce
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (ct *Ciphertext) WriteTo(w io.Writer) (int64, error) {
	if ct == nil {
		return 0, io.ErrUnexpectedEOF
	}
	buf := make([]byte, params.BytesCiphertext)
	//ct.c.FillBytes(buf)
	n, err := w.Write(buf)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (*Ciphertext) Domain() string {
	return "Paillier Ciphertext"
}

func (ct *Ciphertext) MarshalBinary() ([]byte, error) {
	return ct.c.MarshalBinary()
}

func (ct *Ciphertext) UnmarshalBinary(data []byte) error {
	ct.c = new(BigInt.Nat)
	return ct.c.UnmarshalBinary(data)
}

func (ct *Ciphertext) Nat() *BigInt.Nat {
	return new(BigInt.Nat).SetNat(ct.c)
}
