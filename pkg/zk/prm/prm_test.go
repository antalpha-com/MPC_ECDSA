package zkprm

import (
	"testing"

	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/pool"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrm(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	sk := paillier.NewSecretKey(pl)
	ped, lambda := sk.GeneratePedersen()

	public := Public{
		ped.N(),
		ped.S(),
		ped.T(),
	}

	proof := NewProof(Private{
		Lambda: lambda,
		Phi:    sk.Phi(),
		P:      sk.P(),
		Q:      sk.Q(),
	}, hash.New(), public, pl)
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

	proofbuf := NewProofMal(Private{
		Lambda: lambda,
		Phi:    sk.Phi(),
		P:      sk.P(),
		Q:      sk.Q(),
	}, hash.New(), public, pl)
	assert.True(t, proofbuf.VerifyMal(public, hash.New(), pl))
	out4, err := cbor.Marshal(proofbuf)

	proof4 := &Proofbuf{}
	require.NoError(t, cbor.Unmarshal(out4, proof4), "failed to unmarshal 2nd proof")

	assert.True(t, proof4.VerifyMal(public, hash.New(), pl))
}

var p *Proof

func BenchmarkCRT(b *testing.B) {
	b.StopTimer()
	pl := pool.NewPool(0)
	defer pl.TearDown()

	sk := paillier.NewSecretKey(pl)
	ped, lambda := sk.GeneratePedersen()

	public := Public{
		ped.N(),
		ped.S(),
		ped.T(),
	}

	private := Private{
		Lambda: lambda,
		Phi:    sk.Phi(),
		P:      sk.P(),
		Q:      sk.Q(),
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		p = NewProof(private, hash.New(), public, nil)
	}
}
