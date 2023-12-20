package zkenc

import (
	"MPC_ECDSA/pkg/math/sample"
	"crypto/rand"
	"github.com/stretchr/testify/require"
	"testing"

	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/zk"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
)

func TestEnc(t *testing.T) {
	group := curve.Secp256k1{}

	verifier := zk.Pedersen
	prover := zk.ProverPaillierPublic

	k := sample.IntervalL(rand.Reader)
	K, rho := prover.Enc(k)
	public := Public{
		K:      K,
		Prover: prover,
		Aux:    verifier,
	}

	proof := NewProof(group, hash.New(), public, Private{
		K:   k,
		Rho: rho,
	})
	assert.True(t, proof.Verify(group, hash.New(), public))

	proofcode := ProofToCode(proof)
	out, _ := cbor.Marshal(proofcode)

	//////////////////////////end Get proof/////////////////////

	proofcode2 := &ProofCode{}
	cbor.Unmarshal(out, proofcode2)
	proof3 := CodeToProof(proofcode2)
	assert.True(t, proof3.Verify(group, hash.New(), public))

	proofbuf := NewProofMal(group, hash.New(), public, Private{
		K:   k,
		Rho: rho,
	})
	assert.True(t, proofbuf.VerifyMal(group, hash.New(), public))
	out4, _ := cbor.Marshal(proofbuf)

	proof4 := &Proofbuf{}
	require.NoError(t, cbor.Unmarshal(out4, proof4), "failed to unmarshal 2nd proof")

	assert.True(t, proof4.VerifyMal(group, hash.New(), public))
}
