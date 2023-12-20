package sign

import (
	mrand "math/rand"
	"testing"

	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/test"
	"MPC_ECDSA/pkg/ecdsa"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/pool"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

// The TestRound function is a test function that tests the execution of a signing protocol round
func TestRound(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	group := curve.Secp256k1{}

	N := 6
	T := N - 1

	t.Log("generating configs")
	configs, partyIDs := test.GenerateConfig(group, N, T, mrand.New(mrand.NewSource(1)), pl)
	t.Log("done generating configs")

	partyIDs = partyIDs[:T+1]
	publicPoint := configs[partyIDs[0]].PublicPoint()

	messageToSign := []byte("hello")
	messageHash := make([]byte, 64)
	sha3.ShakeSum128(messageHash, messageToSign)

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		// Each round session is initialized with the corresponding configuration and starts the signing protocol.
		c := configs[partyID]
		r, err := StartSign(c, partyIDs, messageHash, pl)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}
	//enters a loop to process the rounds until they are completed
	for {
		//call the test.Rounds function, which executes the rounds and returns any error that occurs during the process.
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, &ecdsa.Signature{}, resultRound.Result, "expected taproot signature result")
		signature := resultRound.Result.(*ecdsa.Signature)
		assert.True(t, signature.Verify(publicPoint, messageHash), "expected valid signature")
	}
}
