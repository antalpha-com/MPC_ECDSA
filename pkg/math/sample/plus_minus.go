package sample

import (
	"io"

	"MPC_ECDSA/internal/params"
	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/math/curve"
)

func sampleNeg(rand io.Reader, bits int) *BigInt.Nat {
	buf := make([]byte, bits/8+1)
	mustReadBits(rand, buf)
	//for index, _ := range buf {
	//	buf[index] = 0x01
	//}
	neg := int(buf[0] & 1)
	buf = buf[1:]
	out := new(BigInt.Nat).SetBytes(buf)
	out.Neg(neg)
	return out
}

// IntervalL returns an integer in the range ± 2ˡ, but with constant-time properties.
func IntervalL(rand io.Reader) *BigInt.Nat {
	return sampleNeg(rand, params.L)
}

// IntervalLPrime returns an integer in the range ± 2ˡ', but with constant-time properties.
func IntervalLPrime(rand io.Reader) *BigInt.Nat {
	return sampleNeg(rand, params.LPrime)
}

// IntervalLEps returns an integer in the range ± 2ˡ⁺ᵉ, but with constant-time properties.
func IntervalLEps(rand io.Reader) *BigInt.Nat {
	return sampleNeg(rand, params.LPlusEpsilon)
}

// IntervalLPrimeEps returns an integer in the range ± 2ˡ'⁺ᵉ, but with constant-time properties.
func IntervalLPrimeEps(rand io.Reader) *BigInt.Nat {
	return sampleNeg(rand, params.LPrimePlusEpsilon)
}

// IntervalLN returns an integer in the range ± 2ˡ•N, where N is the size of a Paillier modulus.
func IntervalLN(rand io.Reader) *BigInt.Nat {
	return sampleNeg(rand, params.L+params.BitsIntModN)
}

// IntervalLEpsN returns an integer in the range ± 2ˡ⁺ᵉ•N, where N is the size of a Paillier modulus.
func IntervalLEpsN(rand io.Reader) *BigInt.Nat {
	return sampleNeg(rand, params.LPlusEpsilon+params.BitsIntModN)
}

// IntervalScalar returns an integer in the range ±q, with q the size of a Scalar.
func IntervalScalar(rand io.Reader, group curve.Curve) *BigInt.Nat {
	return sampleNeg(rand, group.ScalarBits())
}
