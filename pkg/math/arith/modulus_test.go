package arith

import (
	"io"
	mrand "math/rand"
	"testing"

	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/math/sample"
	"github.com/stretchr/testify/assert"
)

func sampleCoprime(r io.Reader) (*BigInt.Nat, *BigInt.Nat, *Modulus) {
	p := sample.IntervalLEpsN(r).Abs()
	q := sample.IntervalLEpsN(r).Abs()
	for q.Coprime(p) != 1 {
		q = sample.IntervalLEpsN(r).Abs()
	}
	//cNat := new(BigInt.Nat).Mul(a, b, -1)
	n := new(BigInt.Nat).Mul(p, q, -1)
	pInvQ := new(BigInt.Nat).ModInverse(p, q)
	pNat := new(BigInt.Nat).SetNat(p)
	return p, q, &Modulus{
		n:    n,
		p:    p,
		q:    q,
		pNat: pNat,
		pInv: pInvQ,
	}
}

func TestModulus_Exp(t *testing.T) {
	r := mrand.New(mrand.NewSource(0))
	a, b, c := sampleCoprime(r)

	cFast := ModulusFromFactors(a, b)
	cSlow := new(Modulus)
	cSlow = c
	assert.True(t, cFast.Nat().Eq(cSlow.Nat()) == 1, "n moduli should be the same")

	x := sample.ModN(r, c.n)
	e := sample.IntervalLN(r).Abs()
	eNeg := new(BigInt.Nat).SetNat(e).Neg(1)

	yExpected := new(BigInt.Nat).Exp(x, e, c.n)
	yFast := cFast.Exp(x, e)
	ySlow := cSlow.Exp(x, e)
	assert.True(t, yExpected.Eq(yFast) == 1, "exponentiation with acceleration should give the same result")
	assert.True(t, yExpected.Eq(ySlow) == 1, "exponentiation with acceleration should give the same result")

	yExpected.ExpI(x, eNeg, c.n)
	yFast = cFast.ExpI(x, eNeg)
	ySlow = cSlow.ExpI(x, eNeg)
	assert.True(t, yExpected.Eq(yFast) == 1, "negative exponentiation with acceleration should give the same result")
	assert.True(t, yExpected.Eq(ySlow) == 1, "negative exponentiation with acceleration should give the same result")
}

func benchmarkExpCRT(b *testing.B, m *Modulus, size int) {
	r := mrand.New(mrand.NewSource(0))
	x := new(BigInt.Nat)
	e := new(BigInt.Nat)
	buf := make([]byte, size)
	for i := 0; i < b.N; i++ {
		x = sample.ModN(r, n.n)
		r.Read(buf)
		e.SetBytes(buf)
		m.Exp(x, e)
	}
}
func benchmarkExpICRT(b *testing.B, m *Modulus, size int) {
	r := mrand.New(mrand.NewSource(0))
	x := new(BigInt.Nat)
	e := new(BigInt.Nat)
	buf := make([]byte, size)
	for i := 0; i < b.N; i++ {
		x = sample.ModN(r, n.GetN())
		r.Read(buf)
		e.SetBytes(buf)
		e.Neg(int(r.Uint32() & 1))
		m.ExpI(x, e)
	}
}

func BenchmarkExp(b *testing.B) {
	sizes := map[string]int{
		"256":  256,
		"512":  512,
		"1024": 1024,
		"4096": 4096,
	}
	ms := map[string]*Modulus{
		"fast":        mFast,
		"slow":        mSlow,
		"fastSquared": mSquaredFast,
		"slowSquared": mSquaredSlow,
	}
	for sizeStr, size := range sizes {
		for mStr, m := range ms {
			b.Run(sizeStr+mStr+"Nat", func(b *testing.B) {
				benchmarkExpCRT(b, m, size)
			})
			b.Run(sizeStr+mStr+"Int", func(b *testing.B) {
				benchmarkExpICRT(b, m, size)
			})
		}
	}
}

var (
	p, pSquared, q, qSquared   *BigInt.Nat
	n                          *Modulus
	nSquared                   *BigInt.Nat
	mFast, mSlow               *Modulus
	mSquaredFast, mSquaredSlow *Modulus
)

func init() {
	p, _ = new(BigInt.Nat).SetHex("D08769E92F80F7FDFB85EC02AFFDAED0FDE2782070757F191DCDC4D108110AC1E31C07FC253B5F7B91C5D9F203AA0572D3F2062A3D2904C535C6ACCA7D5674E1C2640720E762C72B66931F483C2D910908CF02EA6723A0CBBB1016CA696C38FEAC59B31E40584C8141889A11F7A38F5B17811D11F42CD15B8470F11C6183802B")
	q, _ = new(BigInt.Nat).SetHex("C21239C3484FC3C8409F40A9A22FABFFE26CA10C27506E3E017C2EC8C4B98D7A6D30DED0686869884BE9BAD27F5241B7313F73D19E9E4B384FABF9554B5BB4D517CBAC0268420C63D545612C9ADABEEDF20F94244E7F8F2080B0C675AC98D97C580D43375F999B1AC127EC580B89B2D302EF33DD5FD8474A241B0398F6088CA7")
	nNat := new(BigInt.Nat).Mul(p, q, -1)
	n = ModulusFromN(nNat)
	mFast = ModulusFromFactors(p, q)
	mSlow = n

	pSquared = new(BigInt.Nat).Mul(p, p, -1)
	qSquared = new(BigInt.Nat).Mul(q, q, -1)
	nSquaredNat := new(BigInt.Nat).Mul(pSquared, qSquared, -1)
	nSquared = nSquaredNat
	mSquaredFast = ModulusFromFactors(pSquared, qSquared)
	mSquaredSlow = ModulusFromN(nSquared)
}
