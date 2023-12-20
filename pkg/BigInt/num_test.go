// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.
package BigInt

import (
	"bytes"
	"crypto/rand"
	"fmt"
	gobig "math/big"
	mrand "math/rand"
	"reflect"
	"testing"
)

func (*Nat) Generate(r *mrand.Rand, size int) reflect.Value {
	bytes := make([]byte, r.Int()&127)
	r.Read(bytes)
	i := new(Nat).SetBytes(bytes)
	return reflect.ValueOf(i)
}
func Test2(t *testing.T) {
	type A struct {
		a1 int
		a2 int
		a3 int
	}
	type B struct {
		b1 int
		b2 int
		b3 A
	}
	var c *A
	c1 := A{1, 2, 3}
	c2 := A{11, 12, 13}
	//c = &c1
	c = new(A)
	fmt.Println(c)
	fmt.Println(c1)
	fmt.Println(c2)
}
func TestAdd1(t *testing.T) {
	a := new(Nat).SetUint64(0xa)
	b := new(Nat).SetUint64(0xb)
	a1 := a.GetSign()
	fmt.Println(a1)
	a2 := a.Neg(1)
	a3 := a2.GetSign()
	fmt.Println(a3)
	fmt.Println(a)
	fmt.Println(b)
	c := new(Nat).SetUint64(0) //这样就可以了
	c = c.Add(a, b, -1)
	//c := new(Nat).Add(a, b, -1) //这样不行，gmp没有初始化，会报错。
	fmt.Println(c)
}
func TestSetBytesExamples1(t *testing.T) {
	var x, z Nat
	x.SetBytes([]byte{0x12, 0x34, 0x56})
	z.SetUint64(0x123456)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetBytes([]byte{0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	xbit := x.Bit(8)
	xlen := x.BitLen()
	fmt.Println(xlen)
	fmt.Println(xbit)
	z.SetUint64(0xAABBCCDDEEFF)
	z.maxbitlen(&x)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
}

func TestBytesExamples1(t *testing.T) {
	var x Nat
	expected := []byte{0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD}
	x.SetBytes(expected)
	out := x.Bytes()
	if !bytes.Equal(expected, out) {
		t.Errorf("%+v != %+v", expected, out)
	}
}

func TestByteExample1(t *testing.T) {
	x := new(Nat).SetBytes([]byte{8, 7, 6, 5, 4, 3, 2, 1, 0})
	for i := 0; i <= 8; i++ {
		expected := byte(i)
		actual := x.Byte(i)
		if expected != actual {
			t.Errorf("%+v != %+v", expected, actual)
		}
	}
}
func TestBigExamples1(t *testing.T) {
	theBytes := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	x := new(Nat).SetBytes(theBytes)
	expected := new(gobig.Int).SetBytes(theBytes)
	actual := x.Big()
	if expected.Cmp(actual) != 0 {
		t.Errorf("%+v != %+v", expected, actual)
	}
	expectedNat := x

	actualNat := new(Nat).SetBig(expected)
	if expectedNat.Eq(actualNat) != 1 {
		t.Errorf("%+v != %+v", expectedNat, actualNat)
	}

}

var uint64Tests = []uint64{
	12,
	34,
	4294967295,
	4294967296,
	8589934591,
	8589934592,
	223372036854775807,
	223372036854775808,
	18446744073709551615, // 1<<64 - 1
}

func TestUint64(t *testing.T) {
	in := new(Nat)
	for i, testVal := range uint64Tests {
		in.SetUint64(testVal)
		out := in.Uint64()

		if out != testVal {
			t.Errorf("#%d got %d want %d", i, out, testVal)
		}

		str := fmt.Sprint(testVal)
		strOut := in.String()
		if strOut != str {
			t.Errorf("#%d.String got %s want %s", i, strOut, str)
		}
	}
}
func TestSetNat(t *testing.T) {
	in := new(Nat)
	a := new(Nat).SetUint64(3)
	in.SetNat(a)
	if in.Cmp(a) != 0 {
		t.Errorf("%+v != %+v", a, in)
	}
}
func TestClone(t *testing.T) {
	a := new(Nat).SetUint64(3)
	b := a.Clone()
	b.SetUint64(4)
	if a.Data == b.Data {
		t.Errorf("%+v != %+v", a, b)
	}
}

func TestAbs(t *testing.T) {
	a := new(Nat).SetUint64(3)
	b := a.Abs()
	c := b.Abs()
	if a.Data == c.Data {
		t.Errorf("%+v != %+v", a, b)
	}
}

/*
	func testAddCommutative(a Nat, b Nat) bool {
		var aPlusB, bPlusA Nat
		for _, x := range []int{256, 128, 64, 32, 8} {
			aPlusB.Add(&a, &b, x)
			bPlusA.Add(&b, &a, x)
			if aPlusB.Eq(&bPlusA) != 1 {
				return false
			}
		}
		return true
	}

	func TestAddCommutative(t *testing.T) {
		//err := quick.Check(testAddCommutative, &quick.Config{})
		err := quick.Check(testAddCommutative, nil)
		if err != nil {
			t.Error(err)
		}
	}
*/

func TestMarshal(t *testing.T) {
	a := new(Nat).SetUint64(33)
	bytes, err := a.MarshalBinary()
	if err != nil {
		t.Errorf("Marshal Error!")
	}
	b := new(Nat).SetUint64(0)
	error := b.UnmarshalBinary(bytes)
	if error != nil {
		t.Errorf("Unmarshal Error!")
	}
	if a.Eq(b) == 0 {
		t.Errorf("%+v != %+v", a, b)
	}
}

func TestNat2goBig(t *testing.T) {
	x := new(Nat).SetUint64(100)
	y := Nat2goBig(x)
	fmt.Println(x)
	fmt.Println(y)
}

func TestSetSign(t *testing.T) {
	x := new(Nat).SetUint64(100)
	y := new(Nat).SetUint64(100)
	x.SetSign(-1)
	fmt.Println(x)
	x.SetSign(1)
	fmt.Println(x)
	if x.Eq(y) == 0 {
		t.Errorf("%+v != %+v", x, y)
	}
}

func TestNot(t *testing.T) {
	x := new(Nat).SetUint64(100)
	y := new(Nat).SetUint64(100)
	x.Not()
	fmt.Println(x)
	x.Not()
	fmt.Println(x)
	if x.Eq(y) == 0 {
		t.Errorf("%+v != %+v", x, y)
	}
}

func TestNat(t *testing.T) {
	x := new(Nat).SetUint64(100)
	y := x.Nat()
	if x.Eq(y) == 0 {
		t.Errorf("%+v != %+v", x, y)
	}
}

func TestUint64Creation(t *testing.T) {
	var x, y Nat
	x.SetUint64(0)
	y.SetUint64(0)
	if x.Eq(&y) != 1 {
		t.Errorf("%+v != %+v", x, y)
	}
	x.SetUint64(1)
	if x.Eq(&y) == 1 {
		t.Errorf("%+v == %+v", x, y)
	}
	x.SetUint64(0x1111)
	y.SetUint64(0x1111)
	if x.Eq(&y) != 1 {
		t.Errorf("%+v != %+v", x, y)
	}
}

func TestAddExamples(t *testing.T) {
	var x, y, z Nat
	x.SetUint64(100)
	y.SetUint64(100)
	z.SetUint64(200)
	x = *x.Add(&x, &y, 8)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	z.SetUint64(300 - 256)
	x = *x.Add(&x, &y, 8)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetUint64(0xf3e5487232169930)
	y.SetUint64(0)
	z.SetUint64(0xf3e5487232169930)
	var x2 Nat
	x2.Add(&x, &y, 128)
	if x2.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
}

func TestSubExamples(t *testing.T) {
	x := new(Nat).SetUint64(100)
	y := new(Nat).SetUint64(200)
	y.Sub(y, x, 8)
	if y.Eq(x) != 1 {
		t.Errorf("%+v != %+v", y, x)
	}
}

func TestMulExamples(t *testing.T) {
	var x, y, z Nat
	x.SetUint64(10)
	y.SetUint64(10)
	z.SetUint64(100)
	x = *x.Mul(&x, &y, 8)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	z.SetUint64(232)
	x = *x.Mul(&x, &y, 8)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
}

func TestModAddExamples(t *testing.T) {
	m := new(Nat).SetUint64(13)
	var x, y, z Nat
	x.SetUint64(40)
	y.SetUint64(40)
	x = *x.ModAdd(&x, &y, m)
	z.SetUint64(2)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
}

func TestModMulExamples(t *testing.T) {
	var x, y, z Nat
	m := new(Nat).SetUint64(13)
	x.SetUint64(40)
	y.SetUint64(40)
	x = *x.ModMul(&x, &y, m)
	z.SetUint64(1)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	m.SetBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 1})
	x.SetUint64(1)
	x = *x.ModMul(&x, &x, m)
	z.SetUint64(1)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	m.SetBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 1})
	x.SetUint64(16390320477281102916)
	y.SetUint64(13641051446569424315)
	x = *x.ModMul(&x, &y, m)
	z.SetUint64(12559215458690093993)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
}

func TestModExamples(t *testing.T) {
	var x, test Nat
	x.SetUint64(40)
	m := new(Nat).SetUint64(13)
	x.Mod(&x, m)
	test.SetUint64(1)
	if x.Eq(&test) != 1 {
		t.Errorf("%+v != %+v", x, test)
	}
	m = m.SetBytes([]byte{13, 0, 0, 0, 0, 0, 0, 0, 1})
	x.SetBytes([]byte{41, 0, 0, 0, 0, 0, 0, 0, 0})
	x.Mod(&x, m)
	test.SetBytes([]byte{1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD})
	if x.Eq(&test) != 1 {
		t.Errorf("%+v != %+v", x, test)
	}
}

func TestMod1Examples(t *testing.T) {
	var x, test Nat
	x.SetUint64(40)
	m := new(Nat).SetUint64(13)
	y := x.Mod1(m)
	test.SetUint64(1)
	if y.Eq(&test) != 1 {
		t.Errorf("%+v != %+v", x, test)
	}
	m = m.SetBytes([]byte{13, 0, 0, 0, 0, 0, 0, 0, 1})
	x.SetBytes([]byte{41, 0, 0, 0, 0, 0, 0, 0, 0})
	y = x.Mod1(m)
	test.SetBytes([]byte{1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD})
	if y.Eq(&test) != 1 {
		t.Errorf("%+v != %+v", x, test)
	}
}

func TestModInverseExamples(t *testing.T) {
	x, z := new(Nat), new(Nat)
	x.SetUint64(2)
	m := new(Nat).SetUint64(13)
	x = x.ModInverse(x, m)
	z.SetUint64(7)
	if x.Eq(z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetUint64(16359684999990746055)
	m.SetUint64(7)
	x = x.ModInverse(x, m)
	z.SetUint64(3)
	if x.Eq(z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetUint64(461423694560)
	m.SetUint64(461423694561)
	z.ModInverse(x, m)
	if x.Eq(z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetHex("2AFAE74A613B0764098D86")
	m.SetHex("2AFAE74A613B0764098D87")
	z.ModInverse(x, m)
	if x.Eq(z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetHex("930330931B69B44B8E")
	m.SetHex("930330931B69B44B8F")
	z.ModInverse(x, m)
	if x.Eq(z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetHex("DDAB4CDD41300C5F9511FE68")
	m.SetHex("DDAB4CDD41300C5F9511FE69")
	z.ModInverse(x, m)
	if x.Eq(z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetHex("A200F1C011C86FFF9A")
	m.SetHex("A200F1C011C86FFF9B")
	z.ModInverse(x, m)
	if x.Eq(z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetHex("E7B6E7C1CCB2CEDE797F87937E")
	m.SetHex("E7B6E7C1CCB2CEDE797F87937F")
	z.ModInverse(x, m)
	if x.Eq(z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
}

func TestExpExamples(t *testing.T) {
	var x, y, z, m Nat
	x.SetUint64(3)
	y.SetUint64(345)
	m.SetUint64(13)
	x = *x.Exp(&x, &y, &m)
	z.SetUint64(1)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	m.SetBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 1})
	x.SetUint64(1)
	y.SetUint64(2)
	x = *x.Exp(&x, &y, &m)
	z.SetUint64(1)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
}

func TestExpIExamples(t *testing.T) {
	var x, y, z, m Nat
	x.SetUint64(3)
	y.SetUint64(345)
	y.Not()
	m.SetUint64(13)
	x = *x.ExpI(&x, &y, &m)
	z.SetUint64(1)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	m.SetBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 1})
	x.SetUint64(1)
	y.SetUint64(2)
	y.Not()
	x = *x.ExpI(&x, &y, &m)
	z.SetUint64(1)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
}

func TestPrimeExamples(t *testing.T) {
	x := new(Nat).SetUint64(7)
	if !x.ProbablyPrime(10) {
		t.Errorf("Not Prime")
	}
	y := new(Nat).SetUint64(5)
	if y.IsUnit(x) != 1 {
		t.Errorf("y is not unit x")
	}
}

func TestSetBytesExamples(t *testing.T) {
	var x, z Nat
	x.SetBytes([]byte{0x12, 0x34, 0x56})
	z.SetUint64(0x123456)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetBytes([]byte{0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	z.SetUint64(0xAABBCCDDEEFF)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
}

func TestBytesExamples(t *testing.T) {
	var x Nat
	expected := []byte{0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD}
	x.SetBytes(expected)
	out := x.Bytes()
	if !bytes.Equal(expected, out) {
		t.Errorf("%+v != %+v", expected, out)
	}
}

func TestByteExample(t *testing.T) {
	x := new(Nat).SetBytes([]byte{8, 7, 6, 5, 4, 3, 2, 1, 0})
	for i := 0; i <= 8; i++ {
		expected := byte(i)
		actual := x.Byte(i)
		if expected != actual {
			t.Errorf("%+v != %+v", expected, actual)
		}
	}
}

func TestModInverseEvenExamples(t *testing.T) {
	var z, x Nat
	x.SetUint64(9)
	m := new(Nat).SetUint64(10)
	x.ModInverse(&x, m)
	z.SetUint64(9)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetUint64(1)
	m.SetUint64(10)
	x.ModInverse(&x, m)
	z.SetUint64(1)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetUint64(19)
	x.ModInverse(&x, m)
	z.SetUint64(9)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetUint64(99)
	x.ModInverse(&x, m)
	z.SetUint64(9)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetUint64(999)
	m.SetUint64(1000)
	x.ModInverse(&x, m)
	z.SetUint64(999)
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	// There's an edge case when the modulus is much larger than the input,
	// in which case when we do m^-1 mod x, we need to first calculate the remainder
	// of m.
	x.SetUint64(3)
	m.SetBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0})
	x.ModInverse(&x, m)
	z.SetBytes([]byte{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAB})
	if x.Eq(&z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
}

func TestModSubExamples(t *testing.T) {
	m := new(Nat).SetUint64(13)
	x := new(Nat).SetUint64(0)
	y := new(Nat).SetUint64(1)
	x.ModSub(x, y, m)
	z := new(Nat).SetUint64(12)
	if x.Eq(z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
}

func TestModNegExamples(t *testing.T) {
	m := new(Nat).SetUint64(13)
	x := new(Nat).SetUint64(0)
	x.ModNeg(x, m)
	z := new(Nat).SetUint64(0)
	if x.Eq(z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
	x.SetUint64(1)
	x.ModNeg(x, m)
	z.SetUint64(12)
	if x.Eq(z) != 1 {
		t.Errorf("%+v != %+v", x, z)
	}
}

func TestCmpExamples(t *testing.T) {
	m := new(Nat).SetUint64(13)
	n := new(Nat).SetUint64(13)
	l := new(Nat).SetUint64(14)
	x := new(Nat).SetUint64(0)
	if m.Cmp(n) != 0 {
		t.Errorf("Cmp Equal Error!")
	}
	if m.Cmp(l) != -1 {
		t.Errorf("Cmp Less Than Error!")
	}
	if m.Cmp(x) != 1 {
		t.Errorf("Cmp Large Than Error!")
	}
}

func TestCmp3Examples(t *testing.T) {
	m := new(Nat).SetUint64(13)
	n := new(Nat).SetUint64(13)
	l := new(Nat).SetUint64(14)
	x := new(Nat).SetUint64(0)
	_, eq, _ := m.Cmp3(n)
	if eq != 1 {
		t.Errorf("Cmp Equal Error!")
	}
	_, _, lt := m.Cmp3(l)
	if lt != 1 {
		t.Errorf("Cmp Less Than Error!")
	}
	gt, _, _ := m.Cmp3(x)
	if gt != 1 {
		t.Errorf("Cmp Large Than Error!")
	}
}

func TestCmpModExamples(t *testing.T) {
	m := new(Nat).SetUint64(13)
	n := new(Nat).SetUint64(13)
	l := new(Nat).SetUint64(14)
	x := new(Nat).SetUint64(0)
	if m.CmpMod(n) != 0 {
		t.Errorf("Cmp Equal Error!")
	}
	if m.CmpMod(l) != -1 {
		t.Errorf("Cmp Less Than Error!")
	}
	if m.CmpMod(x) != 1 {
		t.Errorf("Cmp Large Than Error!")
	}
}

func TestEq0Examples(t *testing.T) {
	x := new(Nat).SetUint64(10)
	if x.EqZero() == 1 {
		t.Errorf("Cmp Not Equal 0 Error!")
	}
	y := new(Nat).SetUint64(0)
	fmt.Println(y.EqZero())
	if y.EqZero() != 1 {
		t.Errorf("Cmp Equal 0 Error!")
	}
}

/*
	func TestModSqrtExamples(t *testing.T) {
		m := new(Nat).SetUint64(13)
		x := new(Nat).SetUint64(4)
		x1 := new(Nat).SetUint64(0)
		x1 = x1.ModSqrt(x, m)
		z := new(Nat).SetUint64(11)
		if x.Eq(z) != 1 {
			t.Errorf("%+v != %+v", x, z)
		}
		m = new(Nat).SetUint64(1)
		x.SetUint64(13)
		x.ModSqrt(x, m)
		if x.EqZero() != 1 {
			t.Errorf("%+v != 0", x)
		}
	}
*/
func TestBigExamples(t *testing.T) {
	theBytes := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	x := new(Nat).SetBytes(theBytes)
	expected := new(gobig.Int).SetBytes(theBytes)
	actual := x.Big()
	if expected.Cmp(actual) != 0 {
		t.Errorf("%+v != %+v", expected, actual)
	}
	expectedNat := x
	actualNat := new(Nat).SetBig(expected)
	if expectedNat.Eq(actualNat) != 1 {
		t.Errorf("%+v != %+v", expectedNat, actualNat)
	}
}

func TestDivExamples(t *testing.T) {
	x := new(Nat).SetUint64(64)
	n := new(Nat).SetUint64(2)

	expectedNat := new(Nat).SetUint64(32)
	actualNat := new(Nat).Div(x, n)
	if expectedNat.Eq(actualNat) != 1 {
		t.Errorf("%+v != %+v", expectedNat, actualNat)
	}

	n.SetUint64(1)
	actualNat.Div(x, n)
	if x.Eq(actualNat) != 1 {
		t.Errorf("%+v != %+v", x, actualNat)
	}
}

func TestCoprimeExamples(t *testing.T) {
	x := new(Nat).SetUint64(5 * 7 * 13)
	y := new(Nat).SetUint64(3 * 7 * 11)
	expected := 0
	actual := x.Coprime(y)
	if expected != actual {
		t.Errorf("%+v != %+v", expected, actual)
	}
	x.SetUint64(2)
	y.SetUint64(13)
	expected = 1
	actual = x.Coprime(y)
	if expected != actual {
		t.Errorf("%+v != %+v", expected, actual)
	}
	x.SetUint64(13)
	y.SetUint64(2)
	expected = 1
	actual = x.Coprime(y)
	if expected != actual {
		t.Errorf("%+v != %+v", expected, actual)
	}
	x.SetUint64(2 * 13 * 11)
	y.SetUint64(2 * 5 * 7)
	expected = 0
	actual = x.Coprime(y)
	if expected != actual {
		t.Errorf("%+v != %+v", expected, actual)
	}

	// check x,y with 0 limbs
	x = new(Nat)
	y = new(Nat)
	expected = 0
	actual = x.Coprime(y)
	if expected != actual {
		t.Errorf("%+v != %+v", expected, actual)
	}

	// check x,y=0 with 1 empty limb
	x.SetUint64(0)
	y.SetUint64(0)
	expected = (0)
	actual = x.Coprime(y)
	if expected != actual {
		t.Errorf("%+v != %+v", expected, actual)
	}
}

func TestHexExamples(t *testing.T) {
	x := new(Nat).SetUint64(0x0123456789ABCDEF)
	expected := "0123456789ABCDEF"
	actual := x.Hex()
	if expected != actual {
		t.Errorf("%+v != %+v", expected, actual)
	}
	x.SetHex("0123456789ABCDEF")
	expectedNat := new(Nat).SetUint64(0x0123456789ABCDEF)
	if expectedNat.Eq(x) != 1 {
		t.Errorf("%+v != %+v", expectedNat, x)
	}
}

func TestDivEdgeCase(t *testing.T) {
	x, _ := new(Nat).SetHex("B857C2BFBB8F9C8529B37228BE59017114876E17623A605308BFF084CBA97565BC97F9A2ED65895572B157AF6CADE2D7DD018772149E3216DA6D5B57EA703AF1598E23F3A79637C3072053427732C9E336AF983AB8FFD4F0AD08F042C8D3709FC6CC7247AE6C5D1181183FDBC4A1252D6B8C124FF50D6C72579AC2EC75F79FFD040F61F771D8E4116B40E595DB898A702DC99A882A37F091CDC897171921D744E5F2ACA5F466E4D9087B8D04E90CA99DBB259329C30CD925E046FFCB0CDB17FF2EB9C7475D4280C14711B1538F1282A2259348EAB246296D03051774D34D968329C336997EA4EEEBE9D8EE2EBAEBEF4B97076DF9431556F219DFEEFB58D9828E6AB9944C6717AD201331C8A12A11544389251E9A80388378F5B5596D129DDB5BC80F4D1AC993F0E6EF65AD7F832189DA2BDA0E642B6F1CDC539F07913FCFD65BCDE7D7CD2B7223D37B3666D58879B8EE61D61CE3683B6168F392B61A7C99F162C12138CD598770CC7604577E67B8A28C96AF7BDCB24CBD9B0E2801A2F122EFF7A21249C65BA49BD39B9F6B62BD4B0B16EBA1B8FC4AA2EFD03AD4D08AE17371D4B0A88020B77BCD072063DE9EB3F1FCC54FD2D35E587A424C7F62090E6A82B4839ED376BC572882E415F0A3277AF19E9A8BD4F19C69BA445ADAEAB178CE6952BE8140B0FACF0E7E045B9B8A54986481F8279D78048959FAB13B41AC11EB12AA4C")
	nNat, _ := new(Nat).SetHex("D93C94E373D1B82924130A345FA7B8664AAFF9F335C0E6E79DCFEF49C88DC444885CA953F12BAA4A67B7B21C2FF6B4EECF6A750C76A456B2C800AFCBD0660CA03CB256A594C0D46B00118D6179F845D91EE0D4AFB2168E0FBFAB9958FE3A831950C8D8F402E4CD72C90128F1AE3BE986CE5FFD2EABC3363DE1EEB71BBC7245F4C78899301031803F0AE5B09C803E5E02E18FFA540202E65C29D1692058C34F34B9C9F42482E31436511B23A80F4642DB06BCE8E7C1B0A54E537418B411E4856277B9EC30C0103E1C7881E85F29AD6F7C27109DEEEC1676EE6A74E9641440A9E1095076CFBDD23FFF84A2C683EB19EBEE82811A8B6771CC7AF01DF85BA8A66FCD")
	//n := ModulusFromNat(nNat)
	expected, _ := new(Nat).SetHex("D93C94E373D1B82924130A345FA7B8664AAFF9F335C0E6E79DCFEF49C88DC444885CA953F12BAA4A67B7B21C2FF6B4EECF6A750C76A456B2C800AFCBD0660CA03CB256A594C0D46B00118D6179F845D91EE0D4AFB2168E0FBFAB9958FE3A831950C8D8F402E4CD72C90128F1AE3BE986CE5FFD2EABC3363DE1EEB71BBC7245F2EEA5667ECBA323F12A6765DBA7C58145553B4CCA69B657C0048E06A6E9DD3AEEA09ADEAF46B7A979D10658FB7F22CAB762145FC368D5C4AAC7453E2BFDFC613134C41630993A75904EF63F91E3388ABAF40867AB499B62473B8FD437BB3FABD24D50FFB92903D6BA33E9E337759456E802FDDA7E3F84D5523442D6A25F058F7C")
	actual := x.Div(x, nNat)
	if expected.Eq(actual) != 1 {
		t.Errorf("%+v != %+v", expected, actual)
	}
	x, _ = new(Nat).SetHex("BC5B56830516E486DD0C5C76DF5838511BF68ECB4503FDE3A76C")
	n1 := new(Nat).SetUint64(0xDF)
	expected, _ = new(Nat).SetHex("D83AEF5E2848331DB0D83C3A6690E5F5CB268613D33F212A14")
	actual = x.Div(x, n1)
	if expected.Eq(actual) != 1 {
		t.Errorf("%+v != %+v", expected, actual)
	}
}

func TestLshExamples(t *testing.T) {
	x := new(Nat).SetUint64(1)
	expected := new(Nat).SetUint64(32)
	actual := x.Lsh(x, 5, -1)
	if expected.Eq(actual) != 1 {
		t.Errorf("%+v != %+v", expected, actual)
	}
}

func TestRshExamples(t *testing.T) {
	x := new(Nat).SetUint64(32)
	expected := new(Nat).SetUint64(1)
	actual := x.Rsh(x, 5, -1)
	if expected.Eq(actual) != 1 {
		t.Errorf("%+v != %+v", expected, actual)
	}
}

func TestIsValidExamples(t *testing.T) {
	N := new(Nat).SetUint64(103)
	a := new(Nat).SetUint64(3)
	b := new(Nat).SetUint64(7)
	c := new(Nat).SetUint64(11)
	if !IsValidNatModN(N, a, b, c) {
		t.Errorf("IsValidNatModN Error!")
	}
	if !IsValidBigModN(N, a, b, c) {
		t.Errorf("IsValidBigModN Error!")
	}
	NBig := new(gobig.Int).SetUint64(103)
	aBig := new(gobig.Int).SetUint64(3)
	bBig := new(gobig.Int).SetUint64(7)
	cBig := new(gobig.Int).SetUint64(11)
	if !IsValidBigModN1(NBig, aBig, bBig, cBig) {
		t.Errorf("IsValidBigModN1 Error!")
	}
}

func TestIsInIntervalExamples(t *testing.T) {
	N := new(Nat).SetUint64(103)
	if !IsInIntervalLEps(N) {
		t.Errorf("IsInIntervalLEps Error!")
	}
	if !IsInIntervalLPrimeEps(N) {
		t.Errorf("IsInIntervalLPrimeEps Error!")
	}
}

func TestQNRExamples(t *testing.T) {
	N := new(Nat).SetUint64(103)
	zero := new(Nat).SetUint64(0)
	q := QNR(rand.Reader, N)
	if q.Cmp(N) != -1 && q.Cmp(zero) != 1 {
		t.Errorf("QNR Error!")
	}
}

func TestSetModSymmetricExamples(t *testing.T) {
	N := new(Nat).SetUint64(10)
	Two := new(Nat).SetUint64(2)
	Five := new(Nat).SetUint64(5)
	FiveNeg := Five.Neg(1)
	q := new(Nat).SetModSymmetric(Two, N)
	// fmt.Println(q)
	if q.Cmp(Five) != -1 && q.Cmp(FiveNeg) != 1 {
		t.Errorf("SetModSymmetric Error!")
	}
}

func TestCheckInRangeExamples(t *testing.T) {
	N := new(Nat).SetUint64(10)
	five := new(Nat).SetUint64(5)
	// fmt.Println(five.CheckInRange(N))
	if five.CheckInRange(N) == 1 {
		t.Errorf("CheckInRange Error!")
	}
}

func TestMarshalExample(t *testing.T) {
	n := new(Nat).SetUint64(10)
	nCode := n.MarshalNat()
	n1 := new(Nat).UnmarshalNat(nCode)
	if n.Eq(n1) == 0 {
		t.Errorf("Marshal Error!")
	}
}

/*
func TestModulus_Exp(t *testing.T) {
	r := mrand.New(mrand.NewSource(0))
	a, b, c := sampleCoprime(r)

	cFast := ModulusFromFactors(a, b) //CRT n
	cSlow := ModulusFromN(c)          // common n
	assert.True(t, cFast.Nat().Eq(cSlow.Nat()) == 1, "n moduli should be the same")

	cmod := ModulusFromN(c)
	x := ModN(r, cmod) // generate a x%c
	e := IntervalLN(r).Abs()
	eNeg := new(Nat).SetNat(e).Neg(1)

	yExpected := new(Nat).Exp(x, e, c)
	yFast := cFast.Exp(x, e)
	ySlow := cSlow.Exp(x, e)
	assert.True(t, yExpected.Eq(yFast) == 1, "exponentiation with acceleration should give the same result")
	assert.True(t, yExpected.Eq(ySlow) == 1, "exponentiation with acceleration should give the same result")

	yExpected1 := new(Modulus)
	yExpected1.ExpI()
	yExpected.ExpI(x, eNeg, c)
	yFast = cFast.ExpI(x, eNeg)
	ySlow = cSlow.ExpI(x, eNeg)
	assert.True(t, yExpected.Eq(yFast) == 1, "negative exponentiation with acceleration should give the same result")
	assert.True(t, yExpected.Eq(ySlow) == 1, "negative exponentiation with acceleration should give the same result")
}

var (
	p, pSquared, q, qSquared   *Nat
	n                          *Nat
	nSquared                   *Nat
	mFast, mSlow               *Nat
	mSquaredFast, mSquaredSlow *Nat
)

func init() {
	p, _ := new(Nat).SetHex("D08769E92F80F7FDFB85EC02AFFDAED0FDE2782070757F191DCDC4D108110AC1E31C07FC253B5F7B91C5D9F203AA0572D3F2062A3D2904C535C6ACCA7D5674E1C2640720E762C72B66931F483C2D910908CF02EA6723A0CBBB1016CA696C38FEAC59B31E40584C8141889A11F7A38F5B17811D11F42CD15B8470F11C6183802B")
	q, _ := new(Nat).SetHex("C21239C3484FC3C8409F40A9A22FABFFE26CA10C27506E3E017C2EC8C4B98D7A6D30DED0686869884BE9BAD27F5241B7313F73D19E9E4B384FABF9554B5BB4D517CBAC0268420C63D545612C9ADABEEDF20F94244E7F8F2080B0C675AC98D97C580D43375F999B1AC127EC580B89B2D302EF33DD5FD8474A241B0398F6088CA7")
	nNat := new(Nat).Mul(p, q, -1)
	n := ModulusFromNat(nNat)
	mFast := ModulusFromFactors(p, q)
	mSlow := n

	pSquared = new(Nat).Mul(p, p, -1)
	qSquared = new(Nat).Mul(q, q, -1)
	nSquaredNat := new(Nat).Mul(pSquared, qSquared, -1)
	nSquared = nSquaredNat
	mSquaredFast := ModulusFromFactors(pSquared, qSquared)
	mSquaredSlow = nSquared
	fmt.Println(mSquaredFast)
	fmt.Println(mFast)
	fmt.Println(mSlow)
}
*/
