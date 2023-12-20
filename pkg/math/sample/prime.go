package sample

import (
	big "MPC_ECDSA/pkg/gmp"
	"io"
	"math"
	"sync"

	"MPC_ECDSA/internal/params"
	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/pool"
)

// primes generates an array containing all the odd prime numbers < below
func primes(below uint32) []uint32 {
	sieve := make([]bool, below)
	// Initially, all numbers starting from 2 are considered prime
	for i := 2; i < len(sieve); i++ {
		sieve[i] = true
	}
	// Now, we remove the multiples of every prime number we encounter
	for p := 2; p*p < len(sieve); p++ {
		if !sieve[p] {
			continue
		}
		// p itself is prime, so we don't want to exclude it, but every multiple
		// of p, starting from 2 * p isn't, so we exclude those
		for i := p << 1; i < len(sieve); i += p {
			sieve[i] = false
		}
	}
	// It is believed that there are approximately N / log N primes below N, so this
	// bounds is a decent estimate of our output size
	nF := float64(below)
	out := make([]uint32, 0, int(nF/math.Log(nF)))
	for p := uint32(3); p < below; p++ {
		if sieve[p] {
			out = append(out, p)
		}
	}

	return out
}

// The number of numbers to check after our initial prime guess
const sieveSize = 1 << 18

// The upper bound on the prime numbers used for sieving
const primeBound = 1 << 20

// the number of iterations to use when checking primality
//
// More iterations mean fewer false positives, but more expensive calculations.
//
// 20 is the same number that Go uses internally.
const blumPrimalityIterations = 20

// We want to avoid calculating our prime numbers multiple times, but we also
// don't want to waste time sieving them before they're needed. Using sync.Once
// lets us initialize this array of primes only once, the first time we need them.
var thePrimes []uint32
var initPrimes sync.Once

// We use a large buffer for sieving, but we would like to reuse these buffers
// to avoid allocating a bunch of them.
var sievePool = sync.Pool{
	New: func() interface{} {
		sieve := make([]bool, sieveSize)
		return &sieve
	},
}

func tryBlumPrime(rand io.Reader) *BigInt.Nat {
	initPrimes.Do(func() {
		thePrimes = primes(primeBound)
	})

	bytes := make([]byte, (params.BitsBlumPrime+7)/8)

	_, err := io.ReadFull(rand, bytes)
	if err != nil {
		return nil
	}
	// For both p and (p - 1) / 2 to be prime, it must be the case that p = 3 mod 4

	// Clear low bits to ensure that our number is 3 mod 4
	bytes[len(bytes)-1] |= 3
	// Ensure that the top two bits are set
	//
	// This makes it so that when multiplying two primes generated with this method,
	// the resulting number has twice the number of bits.
	bytes[0] |= 0xC0
	base := new(big.Int).SetBytes(bytes)

	// sieve checks the candidacy of base, base+1, base+2, etc.
	sievePtr := sievePool.Get().(*[]bool)
	sieve := *sievePtr
	defer sievePool.Put(sievePtr)
	for i := 0; i < len(sieve); i++ {
		sieve[i] = true
	}
	// Remove candidates that aren't 3 mod 4
	for i := 1; i+2 < len(sieve); i += 4 {
		sieve[i] = false
		sieve[i+1] = false
		sieve[i+2] = false
	}
	// sieve out primes
	remainder := new(big.Int)
	for _, prime := range thePrimes {
		// We want to eliminate all x = 0, 1 mod r, so we figure out where the
		// next multiple is, relative to base, and eliminate from there.
		//
		// If x = 0 mod r, then x can't be prime. If x = 1 mod r, then (x - 1) / 2
		// can't be prime, so x can't be a safe prime.
		remainder.SetUint64(uint64(prime))
		remainder.Mod(base, remainder)
		r := int(remainder.Uint64())
		primeInt := int(prime)
		firstMultiple := primeInt - r
		if r == 0 {
			firstMultiple = 0
		}
		for i := firstMultiple; i+1 < len(sieve); i += primeInt {
			sieve[i] = false
			sieve[i+1] = false
		}
	}
	p := new(big.Int)
	q := new(big.Int)
	for delta := 0; delta < len(sieve); delta++ {
		if !sieve[delta] {
			continue
		}

		p.SetUint64(uint64(delta))
		p.Add(p, base)
		if p.BitLen() > params.BitsBlumPrime {
			return nil
		}
		// Since p is odd, this is equivalent to (p - 1) / 2
		q.Rsh(p, 1)
		// p is likely to be prime already, so let's first do the other check,
		// which is more likely to fail.
		if !q.ProbablyPrime(blumPrimalityIterations) {
			continue
		}
		// This will do a single iteration of miller rabin, which can be shown
		// to be sufficient when q is prime.
		if !p.ProbablyPrime(0) {
			continue
		}
		res := new(BigInt.Nat).SetUint64(0)
		res.Data.Set(p)
		return res
	}

	return nil
}

// Paillier generate the necessary integers for a Paillier key pair.
// p, q are safe primes ((p - 1) / 2 is also prime), and Blum primes (p = 3 mod 4)
// n = pq.
func Paillier(rand io.Reader, pl *pool.Pool) (p, q *BigInt.Nat) {
	reader := pool.NewLockedReader(rand)
	results := pl.Search(2, func() interface{} {
		q := tryBlumPrime(reader)
		// You have to do this, because of how Go handles nil.
		if q == nil {
			return nil
		}
		return q
	})
	p, q = results[0].(*BigInt.Nat), results[1].(*BigInt.Nat)
	//fmt.Println("p/n   ", p.Hex())
	//fmt.Println("q/n   ", q.Hex())
	//p, _ = new(BigInt.Nat).SetHex("FD90167F42443623D284EA828FB13E374CBF73E16CC6755422B97640AB7FC77FDAF452B4F3A2E8472614EEE11CC8EAF48783CE2B4876A3BB72E9ACF248E86DAA5CE4D5A88E77352BCBA30A998CD8B0AD2414D43222E3BA56D82523E2073730F817695B34A4A26128D5E030A7307D3D04456DC512EBB8B53FDBD1DFC07662099B")
	//q, _ = new(BigInt.Nat).SetHex("DB531C32024A262A0DF9603E48C79E863F9539A82B8619480289EC38C3664CC63E3AC2C04888827559FFDBCB735A8D2F1D24BAF910643CE819452D95CAFFB686E6110057985E93605DE89E33B99C34140EF362117F975A5056BFF14A51C9CD16A4961BE1F02C081C7AD8B2A5450858023A157AFA3C3441E8E00941F8D33ED6B7")
	//p, _ = new(BigInt.Nat).SetHex("C35582B69CF8AE653FB10206293635146801CD6B10278771D29B75C4C12F5EA9A09C414D0F516C407355103DFB2675B66B154B2193C02CA8462D959A5D728754F9E83ABE6E964C938E46AF8D7D253C987BC2AE6F5FCB5D3CD982573A7FB969E48DE72574F159533871CFDA7B170138FC9CB300689F2EDFB0D62058A013B1DB27")
	//q, _ = new(BigInt.Nat).SetHex("EDA3A5F3FACADB89AED1C2F002E619BEED273F9FC122D238CB39B3575D6A08A285D690182C0E53F57AC830FB6FF8201C766ADA5D3379B0ADB7EA5E90DD06A3A934325DF80A1B06E2BFE9AD2A50A14205E912DC5BBC82F86E759C546D0EC048CBEA8733B1B773FFD811BE701C4C0B709781C0018C6C9B9D02D5AE53F33E2B5DB3")
	return
}
