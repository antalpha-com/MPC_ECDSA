package zkmul

import (
	"crypto/rand"
	"testing"

	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/zk"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMul(t *testing.T) {
	group := curve.Secp256k1{}

	prover := zk.ProverPaillierPublic
	x := sample.IntervalL(rand.Reader)
	X, rhoX := prover.Enc(x)

	y := sample.IntervalL(rand.Reader)
	Y, _ := prover.Enc(y)

	C := Y.Clone().Mul(prover, x)
	rho := C.Randomize(prover, nil)

	public := Public{
		X:      X,
		Y:      Y,
		C:      C,
		Prover: prover,
	}
	private := Private{
		X:    x,
		Rho:  rho,
		RhoX: rhoX,
	}

	proof := NewProof(group, hash.New(), public, private)
	assert.True(t, proof.Verify(group, hash.New(), public))

	proofcode := ProofToCode(proof)
	out, err := cbor.Marshal(proofcode)
	require.NoError(t, err, "failed to marshal proof")
	proof2code := &ProofCode{}
	require.NoError(t, cbor.Unmarshal(out, proof2code), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2code)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3code := &ProofCode{}
	require.NoError(t, cbor.Unmarshal(out2, proof3code), "failed to unmarshal 2nd proof")

	proof3 := CodeToProof(proof3code)
	assert.True(t, proof3.Verify(group, hash.New(), public))

	proofbuf := NewProofMal(group, hash.New(), public, private)
	assert.True(t, proofbuf.VerifyMal(group, hash.New(), public))
	out4, _ := cbor.Marshal(proofbuf)

	proof4 := &Proofbuf{}
	require.NoError(t, cbor.Unmarshal(out4, proof4), "failed to unmarshal 2nd proof")

	assert.True(t, proof4.VerifyMal(group, hash.New(), public))
}
