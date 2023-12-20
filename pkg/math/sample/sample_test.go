package sample

import (
	big "MPC_ECDSA/pkg/gmp"
	"crypto/rand"
	// "math/big"
	"testing"

	"MPC_ECDSA/internal/params"
	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/pool"
)

func TestModN(t *testing.T) {
	n := new(BigInt.Nat).SetUint64(3 * 11 * 65519)
	x := ModN(rand.Reader, n)
	lt := x.CmpMod(n)
	if lt != 1 {
		t.Errorf("ModN generated a number >= %v: %v", x, n)
	}
}

const blumPrimeProbabilityIterations = 20

func TestPaillier(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	pNat, _ := Paillier(rand.Reader, pl)
	p := pNat.Data
	if !p.ProbablyPrime(blumPrimeProbabilityIterations) {
		t.Error("BlumPrime generated a non prime number: ", p)
	}
	q := new(big.Int).Sub(p, new(big.Int).SetUint64(1))
	q.Rsh(q, 1)
	if !q.ProbablyPrime(blumPrimeProbabilityIterations) {
		t.Error("p isn't safe because (p - 1) / 2 isn't prime", q)
	}
}

// This exists to save the results of functions we want to benchmark, to avoid
// having them optimized away.
var resultNat *BigInt.Nat

func BenchmarkPaillier(b *testing.B) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	for i := 0; i < b.N; i++ {
		resultNat, _ = Paillier(rand.Reader, pl)
	}
}

func BenchmarkModN(b *testing.B) {
	b.StopTimer()
	nBytes := make([]byte, (params.BitsPaillier+7)/8)
	_, _ = rand.Read(nBytes)
	n := new(BigInt.Nat).SetBytes(nBytes)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultNat = ModN(rand.Reader, n)
	}
}
