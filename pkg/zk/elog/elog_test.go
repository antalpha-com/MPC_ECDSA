package zkelog

import (
	"crypto/rand"
	"testing"

	"MPC_ECDSA/internal/elgamal"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestElog(t *testing.T) {
	group := curve.Secp256k1{}

	H := sample.Scalar(rand.Reader, group).ActOnBase()
	X := sample.Scalar(rand.Reader, group).ActOnBase()
	y := sample.Scalar(rand.Reader, group)
	Y := y.Act(H)

	E, lambda := elgamal.Encrypt(X, y)

	public := Public{
		E:             E,
		ElGamalPublic: X,
		Base:          H,
		Y:             Y,
	}

	proof := NewProof(group, hash.New(), public, Private{
		Y:      y,
		Lambda: lambda,
	})
	assert.True(t, proof.Verify(hash.New(), public))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := Empty(group)
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := Empty(group)
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(hash.New(), public))

	proofbuf := NewProofMal(group, hash.New(), public, Private{
		Y:      y,
		Lambda: lambda,
	})
	assert.True(t, proofbuf.VerifyMal(group, hash.New(), public))
	out4, _ := cbor.Marshal(proofbuf)

	proof4 := &Proofbuf{}
	require.NoError(t, cbor.Unmarshal(out4, proof4), "failed to unmarshal 2nd proof")

	assert.True(t, proof4.VerifyMal(group, hash.New(), public))
}
