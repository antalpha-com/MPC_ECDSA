package zknth

import (
	"crypto/rand"
	"testing"

	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/pool"
	"MPC_ECDSA/pkg/zk"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNth(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := zk.VerifierPaillierPublic
	NMod := N.N()
	rho := sample.UnitModN(rand.Reader, NMod)
	r := new(BigInt.Nat).Exp(rho, NMod, N.ModulusSquared())

	public := Public{N: N, R: r}
	proof := NewProof(hash.New(), public, Private{
		Rho: rho,
	})
	assert.True(t, proof.Verify(hash.New(), public))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")
	assert.True(t, proof3.Verify(hash.New(), public))

	proofbuf := NewProofMal(hash.New(), public, Private{
		Rho: rho,
	})
	assert.True(t, proofbuf.VerifyMal(hash.New(), public))
	out4, _ := cbor.Marshal(proofbuf)

	proof4 := &Proofbuf{}
	require.NoError(t, cbor.Unmarshal(out4, proof4), "failed to unmarshal 2nd proof")

	assert.True(t, proof4.VerifyMal(hash.New(), public))
}
