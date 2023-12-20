package sample

import (
	"MPC_ECDSA/internal/params"
	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/math/curve"
	"fmt"
	"io"
)

// IsInIntervalLEps returns true if n ∈ [-2ˡ⁺ᵉ,…,2ˡ⁺ᵉ].
func IsInIntervalLEps(n *BigInt.Nat) bool {
	if n == nil {
		return false
	}
	return n.BitLen() <= params.LPlusEpsilon
}

// IsInIntervalLPrimeEps returns true if n ∈ [-2ˡ'⁺ᵉ,…,2ˡ'⁺ᵉ].
func IsInIntervalLPrimeEps(n *BigInt.Nat) bool {
	if n == nil {
		return false
	}
	return n.BitLen() <= params.LPrimePlusEpsilon
}

const maxIterations = 255

var ErrMaxIterations = fmt.Errorf("sample: failed to generate after %d iterations", maxIterations)

func mustReadBits(rand io.Reader, buf []byte) {
	for i := 0; i < maxIterations; i++ {
		if _, err := io.ReadFull(rand, buf); err == nil {
			return
		}
	}
	panic(ErrMaxIterations)
}

// ModN samples an element of ℤₙ.
func ModN(rand io.Reader, n *BigInt.Nat) *BigInt.Nat {
	out := new(BigInt.Nat)
	buf := make([]byte, (n.BitLen()+7)/8)
	for {
		mustReadBits(rand, buf)
		///////////////
		//for index, _ := range buf {
		//	buf[index] = 0x01
		//}

		out.SetBytes(buf)
		lt := out.CmpMod(n)
		if lt == -1 {
			break
		}
	}
	return out
}

// UnitModN returns a u ∈ ℤₙˣ.
func UnitModN(rand io.Reader, n *BigInt.Nat) *BigInt.Nat {
	out := new(BigInt.Nat)
	buf := make([]byte, (n.BitLen()+7)/8)
	for i := 0; i < maxIterations; i++ {
		// PERF: Reuse buffer instead of allocating each time
		mustReadBits(rand, buf)

		///////////////
		//for index, _ := range buf {
		//	buf[index] = 01
		//}

		out.SetBytes(buf)
		if out.IsUnit(n) == 1 {
			return out
		}
	}
	panic(ErrMaxIterations)
}

// QNR samples a random quadratic non-residue in Z_n.
func QNR(rand io.Reader, n *BigInt.Nat) *BigInt.Nat {
	return BigInt.QNR(rand, n)
}

// Pedersen generates the s, t, λ such that s = tˡ.
func Pedersen(rand io.Reader, phi *BigInt.Nat, n *BigInt.Nat) (s, t, lambda *BigInt.Nat) {
	lambda = ModN(rand, phi)

	tau := UnitModN(rand, n)
	// t = τ² mod N
	t = tau.ModMul(tau, tau, n)
	// s = tˡ mod N
	// TODO SPEED
	s = new(BigInt.Nat).Exp(t, lambda, n)

	return
}

// Scalar returns a new *curve.Scalar by reading bytes from rand.
func Scalar(rand io.Reader, group curve.Curve) curve.Scalar {
	buffer := make([]byte, group.SafeScalarBytes())
	mustReadBits(rand, buffer)
	//for index, _ := range buffer {
	//	buffer[index] = 0x01
	//}

	n := new(BigInt.Nat).SetBytes(buffer)
	return group.NewScalar().SetNat(n)
}

// ScalarUnit returns a new *curve.Scalar by reading bytes from rand.
func ScalarUnit(rand io.Reader, group curve.Curve) curve.Scalar {
	for i := 0; i < maxIterations; i++ {
		s := Scalar(rand, group)
		if !s.IsZero() {
			return s
		}
	}
	panic(ErrMaxIterations)
}

// ScalarPointPair returns a new *curve.Scalar/*curve.Point tuple (x,X) by reading bytes from rand.
// The tuple satisfies X = x⋅G where G is the base point of the curve.
func ScalarPointPair(rand io.Reader, group curve.Curve) (curve.Scalar, curve.Point) {
	s := Scalar(rand, group)
	return s, s.ActOnBase()
}
