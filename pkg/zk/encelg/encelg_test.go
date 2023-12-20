package zkencelg

import (
	"crypto/rand"
	"github.com/stretchr/testify/require"
	"testing"

	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/zk"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
)

func TestEnc(t *testing.T) {
	group := curve.Secp256k1{}
	verifier := zk.Pedersen
	prover := zk.ProverPaillierPublic

	x := sample.IntervalL(rand.Reader)
	xScalar := group.NewScalar().SetNat(x.Mod1(group.Order()))

	a := sample.Scalar(rand.Reader, group)
	b := sample.Scalar(rand.Reader, group)
	abx := group.NewScalar().Set(a).Mul(b).Add(xScalar)

	A := a.ActOnBase()
	B := b.ActOnBase()
	X := abx.ActOnBase()

	C, rho := prover.Enc(x)
	public := Public{
		C:      C,
		A:      A,
		B:      B,
		X:      X,
		Prover: prover,
		Aux:    verifier,
	}

	proof := NewProof(group, hash.New(), public, Private{
		X:   x,
		Rho: rho,
		A:   a,
		B:   b,
	})
	assert.True(t, proof.Verify(hash.New(), public))

	proofcode := ProofToCode(proof)
	out, _ := cbor.Marshal(proofcode)

	//////////////////////////end Get proof/////////////////////
	proofcode2 := EmptyCode(group)
	cbor.Unmarshal(out, proofcode2)
	proof3 := CodeToProof(proofcode2)

	assert.True(t, proof3.Verify(hash.New(), public))

	proofbuf := NewProofMal(group, hash.New(), public, Private{
		X:   x,
		Rho: rho,
		A:   a,
		B:   b,
	})
	assert.True(t, proofbuf.VerifyMal(group, hash.New(), public))
	out4, _ := cbor.Marshal(proofbuf)

	proof4 := &Proofbuf{}
	require.NoError(t, cbor.Unmarshal(out4, proof4), "failed to unmarshal 2nd proof")

	assert.True(t, proof4.VerifyMal(group, hash.New(), public))
}
