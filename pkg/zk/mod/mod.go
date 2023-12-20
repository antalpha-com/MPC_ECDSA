package zkmod

import (
	"MPC_ECDSA/internal/params"
	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/pool"
	"crypto/rand"
	"github.com/fxamacker/cbor/v2"
)

type Public struct {
	// N = p*q
	N *BigInt.Nat
}

type Private struct {
	// P, Q primes such that
	// P, Q ≡ 3 mod 4
	P, Q *BigInt.Nat
	// Phi = ϕ(n) = (p-1)(q-1)
	Phi *BigInt.Nat
}
type Response struct {
	// A, B s.t. y' = (-1)ᵃ wᵇ y
	A, B bool
	// X = y' ^ {1/4}
	X *BigInt.Nat
	// Z = y^{N⁻¹ mod ϕ(N)}
	Z *BigInt.Nat
}

type Proof struct {
	W         *BigInt.Nat
	Responses [params.StatParam]Response
}

// Proofbuf is used to store the byte stream during communication
type Proofbuf struct {
	Malbuf []byte
}

// isQRModPQ checks that y is a quadratic residue mod both p and q.
//
// p and q should be prime numbers.
//
// pHalf should be (p - 1) / 2
//
// qHalf should be (q - 1) / 2.
func isQRmodPQ(y, pHalf, qHalf *BigInt.Nat, p, q *BigInt.Nat) int {
	oneNat := new(BigInt.Nat).SetUint64(1)
	test := new(BigInt.Nat)
	test.Exp(y, pHalf, p)
	pOk := test.Eq(oneNat)

	test.Exp(y, qHalf, q)
	qOk := test.Eq(oneNat)

	return pOk & qOk
}

// fourthRootExponent returns the 4th root modulo n, or a quadratic residue qr, given that:
//   - n = p•q
//   - phi = (p-1)(q-1)
//   - p,q = 3 (mod 4)  =>  n = 1 (mod 4)
//   - Jacobi(qr, p) == Jacobi(qr, q) == 1
//
// Set e to
//
//	     ϕ + 4
//	e' = ------,   e = (e')²
//	       8
//
// Then, (qrᵉ)⁴ = qr.
func fourthRootExponent(phi *BigInt.Nat) *BigInt.Nat {
	e := new(BigInt.Nat).SetUint64(4)
	tmp1 := new(BigInt.Nat).SetUint64(0)
	tmp1.Add(e, phi, -1)
	tmp2 := new(BigInt.Nat).SetUint64(0)
	tmp2.Rsh(tmp1, 3, -1)
	tmp := new(BigInt.Nat).SetUint64(0)
	tmp.ModMul(tmp2, tmp2, phi)
	e.SetNat(tmp)
	return e
}

// makeQuadraticResidue return a, b and y' such that:
//
//	 y' = (-1)ᵃ • wᵇ • y
//	is a QR.
//
// With:
//   - n=pq is a blum integer
//   - w is a quadratic non residue in Zn
//   - y is an element that may or may not be a QR
//   - pHalf = (p - 1) / 2
//   - qHalf = (p - 1) / 2
//
// Leaking the return values is fine, but not the input values related to the factorization of N.
func makeQuadraticResidue(y, w, pHalf, qHalf *BigInt.Nat, n, p, q *BigInt.Nat) (a, b bool, out *BigInt.Nat) {
	out = new(BigInt.Nat).Mod(y, n)

	if isQRmodPQ(out, pHalf, qHalf, p, q) == 1 {
		return
	}

	// multiply by -1
	out.ModNeg(out, n)
	a, b = true, false
	if isQRmodPQ(out, pHalf, qHalf, p, q) == 1 {
		return
	}

	// multiply by w again
	out.ModMul(out, w, n)
	a, b = true, true
	if isQRmodPQ(out, pHalf, qHalf, p, q) == 1 {
		return
	}

	// multiply by -1 again
	out.ModNeg(out, n)
	a, b = false, true
	return
}

func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}

	N := public.N
	if BigInt.Jacobi(p.W, N) != -1 {
		return false
	}

	if !BigInt.IsValidBigModN(N, p.W) {
		return false
	}
	for _, r := range p.Responses {
		if !BigInt.IsValidBigModN(N, r.X, r.Z) {
			return false
		}
	}

	return true
}

// NewProof generates a proof that:
//   - n = pq
//   - p and q are odd primes
//   - p, q == 3 (mod n)
//
// With:
//   - W s.t. (w/N) = -1
//   - x = y' ^ {1/4}
//   - z = y^{N⁻¹ mod ϕ(N)}
//   - a, b s.t. y' = (-1)ᵃ wᵇ y
//   - R = [(xᵢ aᵢ, bᵢ), zᵢ] for i = 1, …, m
func NewProof(hash *hash.Hash, private Private, public Public, pl *pool.Pool) *Proof {
	n, p, q, phi := public.N, private.P, private.Q, private.Phi
	pHalf := new(BigInt.Nat).Rsh(p, 1, -1)
	pMod := new(BigInt.Nat).SetNat(p)
	qHalf := new(BigInt.Nat).Rsh(q, 1, -1)
	qMod := new(BigInt.Nat).SetNat(q)
	phiMod := new(BigInt.Nat).SetNat(phi)
	// W can be leaked so no need to make this sampling return a nat.
	w := sample.QNR(rand.Reader, n)
	//w, _ := new(BigInt.Nat).SetHex("6711580511585285046518328459559353427199602915156334502584794332150512926717975222457416932844010925975837340931752192361888495907878968414565584964145894560520111636375334068583753927958302532998235145609674121400268151764779648637168204119292126890486578197579401763685935716760180566845490152139416340336642759564585089462540837150774082571467567528972266941832602095243378689371293499912585193885114667968076645261307763335527402205236328902628255149089528074130015843295170083960823756285321874709375379221713576505928031521076375341323423082607321386913843100825650348509918302437057085948357760363686134031383")
	//fmt.Println("QNR_w", w.Hex())
	//BigInt.Printhexox(w)

	//sss := []byte{0x55, 0x87, 0x3A, 0x10, 0x0B, 0xCB, 0xB3, 0xD0, 0x52, 0xC1, 0x7C, 0x0C, 0xA3, 0x55, 0x68, 0x97, 0xC5, 0xC3, 0x18, 0x7C, 0xE2, 0x8B, 0x27, 0xE8, 0x3C, 0x96, 0x9A, 0xED, 0xDB, 0x41, 0x03, 0x7D, 0xE8, 0x30, 0xA3, 0x7D, 0x29, 0x26, 0x4B, 0x5D, 0xAD, 0x27, 0x0E, 0xE2, 0x65, 0x41, 0x7F, 0x32, 0x71, 0x9B, 0x16, 0x87, 0xEF, 0x34, 0xCD, 0x52, 0x0A, 0x02, 0x19, 0x23, 0x2F, 0x96, 0x2B, 0x0E, 0x81, 0x33, 0xF9, 0xBB, 0xA9, 0x3C, 0xFD, 0x55, 0xAC, 0x23, 0x3B, 0x2B, 0x8A, 0xF4, 0x23, 0xAE, 0xBD, 0xE2, 0x59, 0x0C, 0x96, 0x10, 0x46, 0xBB, 0x05, 0xF6, 0xCB, 0x5A, 0xB4, 0xE5, 0x10, 0x73, 0x90, 0xE0, 0xCE, 0xB0, 0x03, 0x4A, 0x82, 0xBD, 0xA9, 0x0C, 0x88, 0xDB, 0xB7, 0x9B, 0xF0, 0xC7, 0x8C, 0x3D, 0x50, 0x98, 0xCB, 0x96, 0x09, 0x0E, 0x1C, 0xFA, 0xAD, 0x0D, 0x04, 0x03, 0x88, 0x19, 0xBF, 0x27, 0x07, 0x5F, 0xC6, 0x02, 0x6E, 0x4B, 0xA1, 0xE7, 0x6D, 0x68, 0xAC, 0x36, 0xBC, 0x63, 0xFC, 0x9E, 0x16, 0xDC, 0x52, 0x22, 0x65, 0x27, 0x4E, 0x15, 0x5B, 0xC7, 0xB2, 0x88, 0xBA, 0x56, 0x44, 0x58, 0x77, 0x63, 0x44, 0x72, 0xFE, 0x5E, 0xC2, 0xA1, 0xB3, 0x33, 0x81, 0x2C, 0x08, 0xBB, 0x50, 0x62, 0xD7, 0xB4, 0x90, 0x2D, 0xD0, 0x6A, 0x23, 0x9F, 0x1E, 0x36, 0x52, 0xA5, 0x35, 0xE6, 0xC3, 0xB5, 0xA5, 0xE7, 0x98, 0xDA, 0xC5, 0xDE, 0x8A, 0xDB, 0x4B, 0xCA, 0x8B, 0x4F, 0x1A, 0x5F, 0x85, 0xD0, 0x34, 0xB8, 0x72, 0x43, 0xBA, 0x21, 0xB9, 0x95, 0x19, 0x83, 0x54, 0x38, 0x86, 0xEE, 0x00, 0x84, 0xF4, 0xB1, 0xAE, 0xA8, 0xD4, 0x4C, 0x62, 0x5C, 0x59, 0xD9, 0xC7, 0xB3, 0x48, 0x9A, 0x56, 0xC3, 0xB8, 0x7F, 0x10, 0xBB, 0xD6, 0xE2, 0x24, 0xC3, 0xF3, 0x65, 0x94, 0x13, 0x55, 0x99}
	//w := new(BigInt.Nat).SetBytes(sss)
	nInverse := new(BigInt.Nat).ModInverse(n, phiMod)

	e := fourthRootExponent(phi)
	ys, _ := challenge(hash, n, w)

	var rs [params.StatParam]Response
	pl.Parallelize(params.StatParam, func(i int) interface{} {
		y := ys[i]
		z := new(BigInt.Nat).Exp(y, nInverse, n)
		//fmt.Println("z", z)
		a, b, yPrime := makeQuadraticResidue(y, w, pHalf, qHalf, n, pMod, qMod)
		// X = (y')¹/4
		x := new(BigInt.Nat).Exp(yPrime, e, n)
		//fmt.Println("x", x)
		rs[i] = Response{
			A: a,
			B: b,
			X: x,
			Z: z,
		}

		return nil
	})

	return &Proof{
		W:         w,
		Responses: rs,
	}
}

func NewProof222(hash *hash.Hash, private Private, public Public, pl *pool.Pool) *Proof {
	n, p, q, phi := public.N, private.P, private.Q, private.Phi
	pHalf := new(BigInt.Nat).Rsh(p, 1, -1)
	pMod := new(BigInt.Nat).SetNat(p)
	qHalf := new(BigInt.Nat).Rsh(q, 1, -1)
	qMod := new(BigInt.Nat).SetNat(q)
	phiMod := new(BigInt.Nat).SetNat(phi)
	// W can be leaked so no need to make this sampling return a nat.
	w := sample.QNR(rand.Reader, n)

	nInverse := new(BigInt.Nat).ModInverse(n, phiMod)

	e := fourthRootExponent(phi)
	ys, _ := challenge(hash, n, w)

	var rs [params.StatParam]Response
	pl.Parallelize(params.StatParam, func(i int) interface{} {
		y := ys[i]
		z := new(BigInt.Nat).Exp(y, nInverse, n)
		//fmt.Println("z", z)
		a, b, yPrime := makeQuadraticResidue(y, w, pHalf, qHalf, n, pMod, qMod)
		// X = (y')¹/4
		x := new(BigInt.Nat).Exp(yPrime, e, n)
		//fmt.Println("x", x)
		rs[i] = Response{
			A: a,
			B: b,
			X: x,
			Z: z,
		}

		return nil
	})

	pr := Proof{
		W:         w,
		Responses: rs,
	}

	flag := pr.Verify(public, hash, pl)
	if !flag {
		println(flag)
	}

	return &Proof{
		W:         w,
		Responses: rs,
	}
}

func (r *Response) Verify(n, w, y *BigInt.Nat) bool {
	lhs := new(BigInt.Nat).SetUint64(0)
	rhs := new(BigInt.Nat).SetUint64(0)

	// lhs = zⁿ mod n
	lhs.Exp(r.Z, n, n)
	if lhs.Cmp(y) != 0 {
		return false
	}

	// lhs = x⁴ (mod n)
	lhs.Mul(r.X, r.X, -1)
	lhs.Mul(lhs, lhs, -1)
	lhs.Mod(lhs, n)

	// rhs = y' = (-1)ᵃ • wᵇ • y
	rhs.SetNat(y)
	if r.A {
		rhs.Not() //
	}
	if r.B {
		rhs.Mul(rhs, w, -1)
	}
	rhs.Mod(rhs, n)

	return lhs.Cmp(rhs) == 0
}

// Verify checks a Proof is verified
func (p *Proof) Verify(public Public, hash *hash.Hash, pl *pool.Pool) bool {

	if p == nil {
		return false
	}
	n := public.N
	nMod := public.N
	// check if n is odd and prime
	if n.Bit(0) == 0 || n.ProbablyPrime(20) {
		return false
	}

	if BigInt.Jacobi(p.W, n) != -1 {
		return false
	}

	if !BigInt.IsValidBigModN(n, p.W) {
		return false
	}

	// get [yᵢ] <- ℤₙ
	ys, err := challenge(hash, nMod, p.W)
	if err != nil {
		return false
	}
	verifications := pl.Parallelize(params.StatParam, func(i int) interface{} {
		return p.Responses[i].Verify(n, p.W, ys[i])
	})
	for i := 0; i < len(verifications); i++ {
		if !verifications[i].(bool) {
			return false
		}
	}
	return true
}

func challenge(hash *hash.Hash, n *BigInt.Nat, w *BigInt.Nat) (es []*BigInt.Nat, err error) {
	err = hash.WriteAny(n, w)
	es = make([]*BigInt.Nat, params.StatParam)
	for i := range es {
		es[i] = sample.ModN(hash.Digest(), n)
	}
	return
}

// NewProofMal generates a new Proof and Marshal it, return the Proofbuf
func NewProofMal(hash *hash.Hash, private Private, public Public, pl *pool.Pool) *Proofbuf {
	proof := NewProof(hash, private, public, pl)
	// proofcode := ProofToCode(proof)
	buf, _ := cbor.Marshal(proof)
	proofbuf := new(Proofbuf)
	proofbuf.Malbuf = buf //
	return proofbuf
}

// VerifyMal can verify a Proof in Proofbuf Type
func (p *Proofbuf) VerifyMal(public Public, hash *hash.Hash, pl *pool.Pool) bool {
	proof := &Proof{}
	//proofcode := EmptyCode(group)
	cbor.Unmarshal(p.Malbuf, proof)
	// proof := CodeToProof(proofcode)
	return proof.Verify(public, hash, pl)
}
