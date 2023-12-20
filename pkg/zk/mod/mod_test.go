package zkmod

import (
	"MPC_ECDSA/pkg/math/arith"
	"crypto/rand"
	"testing"

	"MPC_ECDSA/pkg/BigInt"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/pool"
	"MPC_ECDSA/pkg/zk"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMod(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	p, q := zk.ProverPaillierSecret.P(), zk.ProverPaillierSecret.Q()
	sk := zk.ProverPaillierSecret
	public := Public{N: sk.PublicKey.N()}
	proof := NewProof(hash.New(), Private{
		P:   p,
		Q:   q,
		Phi: sk.Phi(),
	}, public, pl)
	//fmt.Println("w", proof.W)
	//fmt.Println("Responses", proof.Responses)

	assert.True(t, proof.Verify(public, hash.New(), pl))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(public, hash.New(), pl))

	proofbuf := NewProofMal(hash.New(), Private{
		P:   p,
		Q:   q,
		Phi: sk.Phi(),
	}, public, pl)
	assert.True(t, proofbuf.VerifyMal(public, hash.New(), pl))
	out4, _ := cbor.Marshal(proofbuf)
	proof4 := &Proofbuf{}
	require.NoError(t, cbor.Unmarshal(out4, proof4), "failed to unmarshal 2nd proof")

	assert.True(t, proof4.VerifyMal(public, hash.New(), pl))

	proof.W = new(BigInt.Nat).SetUint64(0)
	for idx := range proof.Responses {
		proof.Responses[idx].X = new(BigInt.Nat).SetUint64(0)
	}

	assert.False(t, proof.Verify(public, hash.New(), pl), "proof should have failed")
}

func Test_set4thRoot(t *testing.T) {
	var p, q uint64 = 311, 331
	pMod := new(BigInt.Nat).SetUint64(p)
	pHalf := new(BigInt.Nat).SetUint64((p - 1) / 2)
	qMod := new(BigInt.Nat).SetUint64(q)
	qHalf := new(BigInt.Nat).SetUint64((q - 1) / 2)
	n := new(BigInt.Nat).SetUint64(p * q)
	phi := new(BigInt.Nat).SetUint64((p - 1) * (q - 1))
	y := new(BigInt.Nat).SetUint64(502)
	w := sample.QNR(rand.Reader, n)

	nCRT := arith.ModulusFromFactors(pMod.Nat(), qMod.Nat())

	a, b, x := makeQuadraticResidue(y, w, pHalf, qHalf, n, pMod, qMod)

	e := fourthRootExponent(phi)
	root := nCRT.Exp(x, e)
	if b {
		y.ModMul(y, w, n)
	}
	if a {
		y.ModNeg(y, n)
	}

	one := new(BigInt.Nat).SetUint64(1)
	assert.NotEqual(t, root, one, "root cannot be 1")
	root.Exp(root, new(BigInt.Nat).SetUint64(4), n)
	assert.True(t, root.Eq(y) == 1, "root^4 should be equal to y")
}

var proof *Proof

func BenchmarkCRT(b *testing.B) {
	b.StopTimer()
	pl := pool.NewPool(0)
	defer pl.TearDown()

	sk := paillier.NewSecretKey(pl)
	ped, _ := sk.GeneratePedersen()

	public := Public{
		ped.N(),
	}

	private := Private{
		Phi: sk.Phi(),
		P:   sk.P(),
		Q:   sk.Q(),
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		proof = NewProof(hash.New(), private, public, nil)
	}
}
