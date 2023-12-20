package zkaffg

import (
	"MPC_ECDSA/pkg/math/sample"
	"crypto/rand"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"testing"

	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/zk"

	"github.com/stretchr/testify/assert"
)

func TestAffG(t *testing.T) {

	group := curve.Secp256k1{}
	verifierPaillier := zk.VerifierPaillierPublic
	verifierPedersen := zk.Pedersen
	prover := zk.ProverPaillierPublic

	c := new(BigInt.Nat).SetUint64(12)
	C, _ := verifierPaillier.Enc(c)
	x := sample.IntervalL(rand.Reader)

	X := group.NewScalar().SetNat(x.Mod1(group.Order())).ActOnBase()

	y := sample.IntervalLPrime(rand.Reader)
	Y, rhoY := prover.Enc(y)

	tmp := C.Clone().Mul(verifierPaillier, x)
	D, rho := verifierPaillier.Enc(y)
	D.Add(verifierPaillier, tmp)
	//fmt.Println("D", D.Nat().Hex())
	public := Public{
		Kv:       C,
		Dv:       D,
		Fp:       Y,
		Xp:       X,
		Prover:   prover,
		Verifier: verifierPaillier,
		Aux:      verifierPedersen,
	}
	private := Private{
		X: x,
		Y: y,
		S: rho,
		R: rhoY,
	}

	proof := NewProof(group, hash.New(), public, private)
	assert.True(t, proof.Verify(hash.New(), public))

	proofcode := ProofToCode(proof)
	out, _ := cbor.Marshal(proofcode)

	//cborMarshal(proof,byte )([byte])
	//	proofcode := proof.ProofToCode()
	//	out, _ := cbor.Marshal(proofcode)
	//}
	//cborUnmarshal{
	//	proofcode := proof.ProofToCode()
	//	out, _ := cbor.Marshal(proofcode)
	//}
	//zk.affg.cborMarshal()
	//////////////////////////end Get proof/////////////////////

	proofcode2 := EmptyCode(group)
	cbor.Unmarshal(out, proofcode2)
	proof3 := CodeToProof(proofcode2)

	assert.True(t, proof3.Verify(hash.New(), public))

	proofbuf := NewProofMal(group, hash.New(), public, private)
	assert.True(t, proofbuf.VerifyMal(group, hash.New(), public))
	out4, _ := cbor.Marshal(proofbuf)

	proof4 := &Proofbuf{}
	require.NoError(t, cbor.Unmarshal(out4, proof4), "failed to unmarshal 2nd proof")

	assert.True(t, proof4.VerifyMal(group, hash.New(), public))

}
