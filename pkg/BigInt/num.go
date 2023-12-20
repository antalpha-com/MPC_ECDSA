// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.
package BigInt

import (
	"MPC_ECDSA/internal/params"
	"MPC_ECDSA/pkg/gmp"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// Nat consists of Int types of gmp
// Nat can represent positive/negative numbers and 0
type Nat struct {
	Data *gmp.Int
}

//BigInt

// Modulus wraps a BigInt.Modulus
// n = p * q
// CRTflag = 1 when CRT is used in Paillier Encrypt
type Modulus struct {
	N       *gmp.Int
	CRTflag int
	p, q    *gmp.Int
	u       *gmp.Int
}

// SetBytes interprets a number in big-endian format, stores it in z, and returns z.
func (z *Nat) SetBytes(buf []byte) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int).SetBytes(buf)
	} else {
		tmp := new(gmp.Int).SetBytes(buf)
		//z.Data = tmp
		z.Data.Set(tmp)
	}
	return z
}

// maxbitlen return the max length of z and y
func (z *Nat) maxbitlen(y *Nat) int {
	zBits := z.Data.BitLen()
	yBits := y.Data.BitLen()
	if zBits > yBits {
		return zBits
	} else {
		return yBits
	}
}

// BitLen return the length of Nat
func (z *Nat) BitLen() int {
	return z.Data.BitLen()
}

// Bytes creates a slice containing the contents of this Nat, in big endian
func (m *Nat) Bytes() []byte {
	if m.Data == nil {
		fmt.Println("eror！Modulus中z.data为空！！")
		panic("Modulus的data为空")
		return nil
	} else {
		return m.Data.Bytes()
	}
}

// Clone returns a copy of this value.
//
// This copy can safely be mutated without affecting the original.
func (z *Nat) Clone() *Nat {
	return new(Nat).SetNat(z)
}

// Bytes creates a slice containing the contents of this Nat, in big endian
//
// This will always fill the output byte slice based on the announced length of this Nat.
// Bit returns the value of the i'th bit of x. That is, it
// returns (x>>i)&1. The bit index i must be >= 0.
func (x *Nat) Bit(i uint) uint {
	zero := new(Nat).SetUint64(1)
	zero.Rsh(x, i, -1)
	byte1 := zero.Byte(0)
	return uint(byte1) & 1
}

// Abs return  a new Nat of the  Abs of z.
func (z *Nat) Abs() *Nat {
	/*
		tmp := new(Nat).SetUint64(0)
		tmp.Data = new(gmp.Int).Abs(z.Data)
		return tmp
	*/
	tmp := new(Nat).SetUint64(0)
	tmp.Data.Abs(z.Data)
	return tmp
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (m *Nat) MarshalBinary() ([]byte, error) {
	if m.Data == nil {
		fmt.Println("eror！Modulus的data为空！！")
		return nil, errors.New("Modulus的data为空！")
	} else {
		return m.Data.Bytes(), nil
	}
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (z *Nat) UnmarshalBinary(buf []byte) error {
	if buf == nil {
		return errors.New("buf为空！")
	} else {
		if z.Data == nil {
			z.Data = new(gmp.Int).SetBytes(buf)

		} else {
			tmp := new(gmp.Int).SetBytes(buf)
			z.Data.Set(tmp)
		}
		return nil
	}
}

// SetHex modifies the value of z to hold a hex string, returning z
//
// The hex string must be in big endian order. If it contains characters
// other than 0..9, A..F, the value of z will be undefined, and an error will
// be returned.
func (z *Nat) SetHex(hex string) (*Nat, error) {
	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.SetString(hex, 16)
	} else {
		tmp, _ := new(gmp.Int).SetString(hex, 16)
		z.Data.Set(tmp)
	}
	return z, nil
}

// the number of bytes to print in the string representation before an underscore
const underscoreAfterNBytes = 4

// String will represent this nat as a convenient Hex string
//
// This shouldn't leak any information about the value of this Nat, only its length.
func (z *Nat) String() string {
	return strings.ToUpper(z.Data.String())
}

// Byte will access the ith byte in this nat, with 0 being the least significant byte.
//
// This will leak the value of i, and panic if i is < 0.
func (z *Nat) Byte(i int) byte {
	if i < 0 {
		panic("negative byte")
	}
	if z.Data == nil {
		fmt.Println("eror！Byte函数中z.limb为空！！")
		panic("z.limb为空")
	} else {
		bytelen := len(z.Data.Bytes())
		return z.Data.Bytes()[bytelen-i-1]
	}
}

// Big converts a Nat into a gmp.Int
func (z *Nat) Big() *big.Int {
	res := new(big.Int)
	// Unfortunate that there's no good way to handle this
	tmpbytes := z.Bytes()
	res.SetBytes(tmpbytes)
	return res
}

// SetBig modifies z to contain the value of x,return z
func (z *Nat) SetBig(x *big.Int) *Nat {
	tmpbytes := x.Bytes()
	z.SetBytes(tmpbytes)
	return z
}

// Nat2goBig converts Nat Type to Int Type of Big, return a new Int of Big
func Nat2goBig(x *Nat) *big.Int {
	t := new(big.Int)
	tmpbytes := x.Bytes()
	t.SetBytes(tmpbytes)
	return t
}

// SetUint64 sets z to x, and returns z
func (z *Nat) SetUint64(x uint64) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int).SetUint64(x)
	} else {
		tmp := new(gmp.Int).SetUint64(x)
		z.Data.Set(tmp)
	}
	return z
}

// Uint64 represents this number as uint64
//
// The behavior of this function is undefined if the announced length of z is > 64.
func (z *Nat) Uint64() uint64 {
	var ret uint64
	ret = z.Data.Uint64()
	return ret
}

// SetNat copies the value of x into z
//
// z will have the same announced length as x.
func (z *Nat) SetNat(x *Nat) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int).SetUint64(0)
		z.Data.Set(x.Data)
	} else {
		z.Data.Set(x.Data)
	}
	return z
}

// Sign returns:
//
//	-1 if x <  0
//	 0 if x == 0
//	+1 if x >  0
//
// SetSign set the Positive or negative to Nat
func (z *Nat) SetSign(sign int) *Nat {
	z.Data.SetSign(sign)
	return z
}

// GetSign return the Sign of Nat
func (z *Nat) GetSign() int {
	return z.Data.Sign()
}

// Neg sets z to -z and returns z only when doit == 1
// Neg will check whether z is nil, if nil return panic
func (z *Nat) Neg(doit int) *Nat {
	if z.Data == nil {
		panic("data为空")

	} else {
		if doit == 1 {
			//tmp := new(gmp.Int).SetUint64(0)
			//tmp.Neg(z.Data)
			//z.Data.Set(tmp)
			z.Data.Neg(z.Data)
		}

	}
	return z
}

// Not inverts the Sign of zNat
func (z *Nat) Not() *Nat {
	if z.Data.Sign() == 0 {
		return z
	}
	if z.Data.Sign() == 1 {
		z.Data.SetSign(-1)
	} else {
		z.Data.SetSign(1)
	}
	return z
}

// Nat returns the value of this Nat as a Nat.
//
// This will create a copy of this Nat value, so the Nat can be safely
// mutated.
func (m *Nat) Nat() *Nat {
	z := new(Nat)
	z.Data = new(gmp.Int)
	z.Data.Set(m.Data)
	return z
}

// Hex will represent this Nat as a Hex string.
//
// The hex string will hold a multiple of 8 bits.
//
// This shouldn't leak any information about the value of the Nat, beyond
// the usual leakage around its size.
func (m *Nat) Hex() string {
	if m.Data == nil {
		return ""
	} else {
		s := m.Data.Hex()

		if len(s)&1 == 1 {
			s = "0" + s
		}
		return s
	}
}

// Mod calculates z <- x mod m and return z
//
// The capacity of the resulting number matches the capacity of the Nat.
func (z *Nat) Mod(x *Nat, m *Nat) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.Mod(x.Data, m.Data)

	} else {
		z.Data.Mod(x.Data, m.Data)
	}
	return z
}

// Mod calculates z mod M, and return a new Nat, handling negatives correctly.
//
// As indicated by the types, this function will return a number in the range 0..m-1.
func (z *Nat) Mod1(m *Nat) *Nat {
	out := new(Nat).Mod(z.Abs(), m)
	negated := new(Nat).ModNeg(out, m)
	tmp := z.GetSign()
	tmpsign := 0
	if tmp == -1 {
		tmpsign = 1
	}
	out.CondAssign(tmpsign, negated)
	return out
}

// Div calculates z <- x / m, with m a Nat. Return z
func (z *Nat) Div(x *Nat, m *Nat) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.Div(x.Data, m.Data)

	} else {
		z.Data.Div(x.Data, m.Data)
	}
	return z
}

// ModAdd calculates z <- x + y mod m and return z
func (z *Nat) ModAdd(x *Nat, y *Nat, m *Nat) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.Add(x.Data, y.Data)
		z.Data.Mod(z.Data, m.Data)

	} else {
		z.Data.Add(x.Data, y.Data)
		z.Data.Mod(z.Data, m.Data)
	}
	return z
}

// ModAdd calculates z <- x - y mod m and return z
func (z *Nat) ModSub(x *Nat, y *Nat, m *Nat) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.Sub(x.Data, y.Data)
		z.Data.Mod(z.Data, m.Data)
	} else {
		z.Data.Sub(x.Data, y.Data)
		z.Data.Mod(z.Data, m.Data)
	}
	return z
}

// ModNeg calculates z <- -x mod n and return z
func (z *Nat) ModNeg(x *Nat, n *Nat) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.Neg(x.Data)
		z.Data.Mod(z.Data, n.Data)
	} else {
		z.Data.Neg(x.Data)
		z.Data.Mod(z.Data, n.Data)
	}
	return z
}

// Add calculates z <- x + y, modulo 2^cap and return z
func (z *Nat) Add(x *Nat, y *Nat, cap int) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.Add(x.Data, y.Data)
	} else {
		z.Data.Add(x.Data, y.Data)
	}
	if cap > 0 {
		modulo := new(gmp.Int).SetUint64(0)
		modulo.Lsh(new(gmp.Int).SetUint64(1), uint(cap))
		z.Data.Mod(x.Data, modulo)
	}
	return z
}

// Sub calculates z <- x - y, modulo 2^cap, and return z
func (z *Nat) Sub(x *Nat, y *Nat, cap int) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.Sub(x.Data, y.Data)
	} else {
		z.Data.Sub(x.Data, y.Data)
	}
	if cap == -1 {
		return z
	} else {
		modulo := new(gmp.Int).SetUint64(0)
		modulo.Lsh(new(gmp.Int).SetUint64(1), uint(cap))
		z.Data.Mod(x.Data, modulo)
		return z
	}
}

// ModMul calculates z <- x * y mod n and return z
func (z *Nat) ModMul(x *Nat, y *Nat, n *Nat) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.ModMul(x.Data, y.Data, n.Data)
	} else {
		z.Data.ModMul(x.Data, y.Data, n.Data)
	}
	return z
}

// Mul calculates z <- x * y, modulo 2^cap, and return z
func (z *Nat) Mul(x *Nat, y *Nat, cap int) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.Mul(x.Data, y.Data)
	} else {
		z.Data.Mul(x.Data, y.Data)
	}
	if cap < 0 {
		return z
	} else {
		modulo := new(gmp.Int).SetUint64(0)
		modulo.Lsh(new(gmp.Int).SetUint64(1), uint(cap))
		z.Data.Mod(x.Data, modulo)
		return z
	}

}

// Rsh calculates z <- x >> shift, producing a certain number of bits
// If cap < 0, the number of bits does not change
func (z *Nat) Rsh(x *Nat, shift uint, cap int) *Nat {

	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.Rsh(x.Data, shift)
	} else {
		z.Data.Rsh(x.Data, shift)
	}
	if cap < 0 {
		return z
	} else {
		modulo := new(gmp.Int).SetUint64(0)
		modulo.Lsh(new(gmp.Int).SetUint64(1), uint(cap))
		z.Data.Mod(x.Data, modulo)
		return z
	}
}

// Lsh calculates z <- x << shift, producing a certain number of bits
// If cap < 0, the number of bits does not change
func (z *Nat) Lsh(x *Nat, shift uint, cap int) *Nat {

	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.Lsh(x.Data, shift)
	} else {
		z.Data.Lsh(x.Data, shift)
	}
	if cap < 0 {
		return z
	} else {
		modulo := new(gmp.Int).SetUint64(0)
		modulo.Lsh(new(gmp.Int).SetUint64(1), uint(cap))
		z.Data.Mod(x.Data, modulo)

		return z
	}
}

// Exp sets z = x**y mod |n| (i.e. the sign of m is ignored), and returns z.
// if z == nil, generate a new z
func (z *Nat) Exp(x *Nat, y *Nat, n *Nat) *Nat {
	if z == nil {
		z = new(Nat).SetUint64(0)
	}
	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.Exp(x.Data, y.Data, n.Data)
	} else {
		z.Data.Exp(x.Data, y.Data, n.Data)
	}
	return z
}

// ExpI sets z = x**y mod |n| (i.e. the sign of m is ignored), and returns z.
// Compared with Exp, ExpI works when y is negetive
func (z *Nat) ExpI(x *Nat, y *Nat, n *Nat) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int)
	}
	tmpy := y.Abs()
	//z.Data.Exp(x.Data, y.Abs().Data, n.Data)
	z.Data.Exp(x.Data, tmpy.Data, n.Data)
	inverted := new(gmp.Int).ModInverse(z.Data, n.Data)
	if y.GetSign() == 1 {
		return z
	} else {
		z.Data = inverted
		return z
	}

}

// Cmp compares two Nats, returning:
//
//	-1 if z <  y
//	 0 if z == y
//	+1 if z >  y
func (z *Nat) Cmp(y *Nat) int {
	if z.Data == nil {
		z.Data = new(gmp.Int)
		return z.Data.Cmp(y.Data)
	} else {
		return z.Data.Cmp(y.Data)
	}
}

// Cmp3 compares two Nats, returning results for (>, =, <) in that order.
//
// Because these relations are mutually exclusive, exactly one of these values
// will be true.
func (z *Nat) Cmp3(x *Nat) (int, int, int) {
	// Rough Idea: Resize both slices to the maximum length, then compare
	// using that length
	eq := 0
	gt := 0
	lt := 0
	res := z.Data.Cmp(x.Data)
	if res < 0 {
		lt = 1
	} else if res == 0 {
		eq = 1
	} else {
		gt = 1
	}
	return gt, eq, lt
}

// CmpMod compares this natural number with a Nat, returning:
//
//	-1 if z <  y
//	 0 if z == y
//	+1 if z >  y
func (z *Nat) CmpMod(y *Nat) int {
	return z.Data.Cmp(y.Data)
}

// Eq checks if z = y. return 1,else return 0
func (z *Nat) Eq(y *Nat) int {
	//_, eq, _ := z.Cmp(y)
	r := z.Data.Cmp(y.Data)
	if r == 0 {
		return 1
	} else {
		return 0
	}

}

// EqZero compares z to 0.
func (z *Nat) EqZero() int {
	zero := new(Nat).SetUint64(0)
	if z.Eq(zero) == 1 {
		return 1
	} else {
		return 0
	}
}

// Coprime returns 1 if gcd(x, y) == 1, and 0 otherwise
func (x *Nat) Coprime(y *Nat) int {
	if x.Data == nil || y.Data == nil {
		return 0
	}
	z := new(Nat).SetUint64(0)
	z.Data.GCD(nil, nil, x.Data, y.Data)
	one := new(Nat).SetUint64(1)
	return z.Eq(one)
}

// ProbablyPrime performs n Miller-Rabin tests to check whether z is prime.
// If it returns true, z is prime with probability 1 - 1/4^n.
// If it returns false, z is not prime.
func (x *Nat) ProbablyPrime(n int) bool {
	return x.Data.ProbablyPrime(n)
}

// Jacobi returns the Jacobi symbol (x/y), which is+1, -1, or 0 The y parameter must be an odd number
func Jacobi(x, y *Nat) int {
	return gmp.Jacobi(x.Data, y.Data)
}

// IsUnit checks if x is a unit, i.e. invertible, mod m.
// This so happens to be when gcd(x, m) == 1.
func (x *Nat) IsUnit(m *Nat) int {
	return x.Coprime(m)
}

// ModInverse calculates z <- x^-1 mod m and return z
//
// This will produce nonsense if the Nat is even.
//
// The capacity of the resulting number matches the capacity of the Nat
func (z *Nat) ModInverse(x *Nat, m *Nat) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int)
		z.Data.ModInverse(x.Data, m.Data)
	} else {
		z.Data.ModInverse(x.Data, m.Data)
	}
	return z
}

// IsValidNatModN checks that ints are all in the range [1,…,N-1] and co-prime to N.
func IsValidNatModN(N *Nat, ints ...*Nat) bool {
	for _, i := range ints {
		if i == nil {
			return false
		}
		if lt := i.CmpMod(N); lt != -1 {
			return false
		}
		if i.IsUnit(N) != 1 {
			return false
		}
	}
	return true
}

// IsValidBigModN checks that ints are all in the range [1,…,N-1] and co-prime to N.
func IsValidBigModN1(N *big.Int, ints ...*big.Int) bool {
	var gcd big.Int
	one := big.NewInt(1)
	for _, i := range ints {
		if i == nil {
			return false
		}
		if i.Sign() != 1 {
			return false
		}
		if i.Cmp(N) != -1 {
			return false
		}
		gcd.GCD(nil, nil, i, N)
		if gcd.Cmp(one) != 0 {
			return false
		}
	}
	return true
}

// IsValidBigModN checks that ints are all in the range [1,…,N-1] and co-prime to N.
func IsValidBigModN(N *Nat, ints ...*Nat) bool {
	gcd := new(Nat).SetUint64(0)
	one := new(Nat).SetUint64(1)
	for _, i := range ints {
		if i == nil {
			return false
		}
		if i.GetSign() == -1 {
			return false
		}
		if i.Cmp(N) != -1 {
			return false
		}
		gcd.Data.GCD(nil, nil, i.Data, N.Data)
		if gcd.Cmp(one) != 0 {
			return false
		}
	}
	return true
}

// IsInIntervalLEps returns true if n ∈ [-2ˡ⁺ᵉ,…,2ˡ⁺ᵉ].
func IsInIntervalLEps(n *Nat) bool {
	if n == nil {
		return false
	}
	return n.BitLen() <= params.LPlusEpsilon
}

// IsInIntervalLPrimeEps returns true if n ∈ [-2ˡ'⁺ᵉ,…,2ˡ'⁺ᵉ].
func IsInIntervalLPrimeEps(n *Nat) bool {
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

// QNR samples a random quadratic non-residue in Z_n.
func QNR(rand io.Reader, n *Nat) *Nat {

	w := new(Nat).SetUint64(0)
	buf := make([]byte, params.BitsIntModN/8)
	for i := 0; i < maxIterations; i++ {
		mustReadBits(rand, buf)
		//////
		//for index, _ := range buf {
		//	buf[index] = 0x02
		//}
		w.SetBytes(buf)
		w.Mod(w, n)
		if gmp.Jacobi(w.Data, n.Data) == -1 {
			//fmt.Println("QNR_w", w.Hex())
			return w
		}
	}

	panic(ErrMaxIterations)
}

//func Printhexox(x *Nat) int {
//	s := x.Hex()
//	fmt.Println(s)
//	for i := 0; i < len(s)-1; i = i + 2 {
//		s1 := s[i : i+2]
//		s1 = "0x" + s1 + ","
//		fmt.Printf("%s", s1)
//	}
//	return 0
//}

// QNR samples a random quadratic non-residue in Z_n.
//func QNR1(rand io.Reader, n *Nat) *Nat {
//	var w big.Int
//	tn := Nat2goBig(n)
//	buf := make([]byte, params.BitsIntModN/8)
//	for i := 0; i < maxIterations; i++ {
//		mustReadBits(rand, buf)
//		//////
//		//for index, _ := range buf {
//		//	buf[index] = 0x02
//		//}
//		fmt.Println(buf)
//
//		w.SetBytes(buf)
//		w.Mod(&w, tn)
//		//wInt := w.IntToBigInt()
//		if big.Jacobi(&w, tn) == -1 {
//			return new(Nat).SetBig(&w)
//		}
//
//	}
//	panic(ErrMaxIterations)
//}

// CondAssign sets z <- yes ? x : z.
//
// This function doesn't leak any information about whether the assignment happened.
//
// The announced size of the result will be the largest size between z and x.
func (z *Nat) CondAssign(yes int, x *Nat) *Nat {
	if yes == 1 {
		return z.SetNat(x)
	} else {
		return z
	}

}

// SetModSymmetric takes a number x mod M, and returns a signed number centered around 0.
//
// This effectively takes numbers in the range:
//
//	{0, .., m - 1}
//
// And returns numbers in the range:
//
//	{-(m - 1)/2, ..., 0, ..., (m - 1)/2}
//
// In the case that m is even, there will simply be an extra negative number.
func (z *Nat) SetModSymmetric(x *Nat, m *Nat) *Nat {
	if z.Data == nil {
		z.Data = new(gmp.Int)
	}

	z.Mod(x, m) //attention
	negated := new(Nat).ModNeg(z.Abs(), m)

	gt := negated.Cmp(z)
	if gt == 1 {
		gt = 1
	} else {
		gt = 0
	}
	negatedLeq := 1 ^ gt
	// Always use the smaller value
	z.CondAssign(negatedLeq, negated)
	// A negative modular number, by definition, will have it's negation <= itself
	if negatedLeq == 1 {
		z.SetSign(-1)
	} else {
		z.SetSign(1)
	}

	return z
}

// CheckInRange checks whether or not this Int is in the range for SetModSymmetric.
func (z *Nat) CheckInRange(m *Nat) int {
	// First check that the absolute value makes sense
	absOk := z.Abs().CmpMod(m)
	if absOk == 1 {
		absOk = 1
	} else {
		absOk = 0
	}

	negated := new(Nat).ModNeg(z.Abs(), m)
	lt := negated.Cmp(z.Abs())
	if lt == 1 {
		lt = 1
	} else {
		lt = 0
	}
	// If the negated value is strictly smaller, then we have a number out of range
	signOk := 1 ^ lt

	return absOk & signOk
}

// Exp implementation using CRT acceleration
// It returns xᵉ (mod n).
func (z *Nat) CRTExpN(x, e, n, p, q, u *Nat) *Nat {

	xp := new(Nat).SetUint64(0)
	xq := new(Nat).SetUint64(0)

	ep := new(Nat).SetUint64(0)
	eq := new(Nat).SetUint64(0)

	one := new(Nat).SetUint64(1)
	ps1 := new(Nat).SetUint64(0)
	qs1 := new(Nat).SetUint64(0)

	ps1.Sub(p, one, -1) // ps1 = p - 1
	qs1.Sub(q, one, -1) // qs1 = q - 1

	xp.Mod(x, p) // xp = x mod p
	xq.Mod(x, q) // xq = x mod q

	//ep.Mod(e,)
	//ep=e mod fai(p),ep=e mod fai(p) is better
	ep.Mod(e, ps1) // ep = e mod ps1
	eq.Mod(e, qs1) // eq = e mod qs1

	xp.Exp(xp, ep, p) // x_p = xpᵉ (mod p)
	xq.Exp(xq, eq, q) // x_q = xqᵉ (mod q)
	// r = x₁ + p₁ ⋅ [p₁⁻¹ (mod p₂)] ⋅ [x₁ - x₂] (mod n)
	if z.Data == nil {
		z.Data = new(gmp.Int).SetUint64(0)
	}
	// r = x₁ + u ⋅ p ⋅ [x₁ - x₂] (mod n)
	z.ModSub(xq, xp, n) // z = xq - xp mod n
	z.ModMul(z, u, n)   // z = z*u mod n
	z.ModMul(z, p, n)   // z = z*p mod n
	z.ModAdd(z, xp, n)
	return z
}
func (z *Nat) CRTExpN2(x, e, n2, p2, q2, p, q, pinv2 *Nat) *Nat {

	xp := new(Nat).SetUint64(0)
	xq := new(Nat).SetUint64(0)

	ep := new(Nat).SetUint64(0)
	eq := new(Nat).SetUint64(0)

	//one := new(Nat).SetUint64(1)
	ps1 := new(Nat).SetUint64(0)
	qs1 := new(Nat).SetUint64(0)

	ps1.Sub(p2, p, -1)
	qs1.Sub(q2, q, -1)

	xp.Mod(x, p2)
	xq.Mod(x, q2)

	//ep.Mod(e,)
	//ep=e mod fai(p),ep=e mod fai(p) is better
	ep.Mod(e, ps1)
	eq.Mod(e, qs1)

	xp.Exp(xp, ep, p2) // x₁ = xᵉ (mod p₁)
	xq.Exp(xq, eq, q2) // x₂ = xᵉ (mod p₂)
	// r = x₁ + p₁ ⋅ [p₁⁻¹ (mod p₂)] ⋅ [x₁ - x₂] (mod n)
	if z.Data == nil {
		z.Data = new(gmp.Int).SetUint64(0)
	}
	z.ModSub(xq, xp, n2)
	z.ModMul(z, pinv2, n2)
	z.ModMul(z, p2, n2)
	z.ModAdd(z, xp, n2)
	return z
}
func (z *Nat) CRTExpN3(x, e, p, q, n *Nat) *Nat {

	xp := new(Nat).SetUint64(0)
	xq := new(Nat).SetUint64(0)

	ep := new(Nat).SetUint64(0)
	eq := new(Nat).SetUint64(0)

	p2 := new(Nat).SetUint64(0)
	q2 := new(Nat).SetUint64(0)
	p2.Mul(p, p, -1)
	q2.Mul(q, q, -1)

	//one := new(Nat).SetUint64(1)
	ps1 := new(Nat).SetUint64(0)
	qs1 := new(Nat).SetUint64(0)

	n2 := new(Nat).SetUint64(0)
	pinv2 := new(Nat).SetUint64(0)

	n2.Mul(n, n, -1)
	pinv2.ModInverse(p2, q2)

	ps1.Sub(p2, p, -1)
	qs1.Sub(q2, q, -1)

	xp.Mod(x, p2)
	xq.Mod(x, q2)

	//ep.Mod(e,)
	//ep=e mod fai(p),ep=e mod fai(p) is better
	ep.Mod(e, ps1)
	eq.Mod(e, qs1)

	xp.Exp(xp, ep, p2) // x₁ = xᵉ (mod p₁)
	xq.Exp(xq, eq, q2) // x₂ = xᵉ (mod p₂)
	// r = x₁ + p₁ ⋅ [p₁⁻¹ (mod p₂)] ⋅ [x₁ - x₂] (mod n)
	if z.Data == nil {
		z.Data = new(gmp.Int).SetUint64(0)
	}
	z.ModSub(xq, xp, n2)
	z.ModMul(z, pinv2, n2)
	z.ModMul(z, p2, n2)
	z.ModAdd(z, xp, n2)
	return z
}

// NatCode is used in Cbor, for Nat will lose the symbol bit during transmission
type NatCode struct {
	Sign uint32
	Data []byte
}

//func NatToNewNat(a *Nat) *NatCode {
//	y := new(NatCode)
//	y.Data = a.Bytes()
//	sign := a.GetSign()
//	if sign == -1 {
//		y.Sign = 1
//	} else {
//		y.Sign = 0
//	}
//	return y
//}

// MarshalNat Converts Nat Type to Natcode Type
func (z *Nat) MarshalNat() *NatCode {
	// TODO(gri): get rid of the []byte/string conversions
	m := new(NatCode)
	sign := z.GetSign()
	if sign == -1 {
		m.Sign = 1
	} else {
		m.Sign = 0
	}
	m.Data = z.Bytes()
	return m
}

// UnmarshalNat Converts Natcode Type to Nat Type
func (z *Nat) UnmarshalNat(a *NatCode) *Nat {
	z.SetBytes(a.Data)
	sign := a.Sign
	if sign == 1 {
		z.SetSign(-1)
	}
	return z
}
