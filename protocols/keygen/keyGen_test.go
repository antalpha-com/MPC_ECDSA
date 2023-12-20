package keygen

import (
	mrand "math/rand"
	"testing"

	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/test"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/pool"
	"MPC_ECDSA/protocols/config"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var group = curve.Secp256k1{}

// checkOutput is used for testing the output of a protocol round
// it takes two parameters: t *testing.T for test assertions and rounds []round.Session which represents the output rounds to be checked.
func checkOutput(t *testing.T, rounds []round.Session) {
	N := len(rounds)
	//create an empty slice newConfigs to store the unmarshalled configurations.
	newConfigs := make([]*config.Config, 0, N)
	//For each round in the rounds slice, it verifies that the round is of type round.Output
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r)
		resultRound := r.(*round.Output)
		require.IsType(t, &config.Config{}, resultRound.Result)
		c := resultRound.Result.(*config.Config)
		marshalledConfig, err := cbor.Marshal(c)
		require.NoError(t, err)
		unmarshalledConfig := config.EmptyConfig(group)
		err = cbor.Unmarshal(marshalledConfig, unmarshalledConfig)
		require.NoError(t, err)
		newConfigs = append(newConfigs, unmarshalledConfig)
	}

	firstConfig := newConfigs[0]
	pk := firstConfig.PublicPoint()
	for _, c := range newConfigs {
		assert.True(t, pk.Equal(c.PublicPoint()), "RID is different")
		assert.Equal(t, firstConfig.RID, c.RID, "RID is different")
		assert.EqualValues(t, firstConfig.ChainKey, c.ChainKey, "ChainKey is different")
		for id, p := range firstConfig.Public {
			assert.True(t, p.ECDSA.Equal(c.Public[id].ECDSA), "ecdsa not the same", id)
			assert.True(t, p.ElGamal.Equal(c.Public[id].ElGamal), "elgamal not the same", id)
			assert.True(t, p.Paillier.Equal(c.Public[id].Paillier), "paillier not the same", id)
			assert.True(t, p.Pedersen.S().Eq(c.Public[id].Pedersen.S()) == 1, "S not the same", id)
			assert.True(t, p.Pedersen.T().Eq(c.Public[id].Pedersen.T()) == 1, "T not the same", id)
			assert.True(t, p.Pedersen.N().Nat().Eq(c.Public[id].Pedersen.N().Nat()) == 1, "N not the same", id)
		}
		data, err := c.MarshalBinary()
		assert.NoError(t, err, "failed to marshal new config", c.ID)
		c2 := config.EmptyConfig(group)
		err = c2.UnmarshalBinary(data)
		assert.NoError(t, err, "failed to unmarshal new config", c.ID)
	}
}

func TestKeygen(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	//The variable N is set to 1, representing the number of parties participating in the key generation protocol.
	N := 1
	partyIDs := test.PartyIDs(N)

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		info := round.Info{
			ProtocolID:       "cmp/keygen-test",
			FinalRoundNumber: Rounds,
			SelfID:           partyID,
			PartyIDs:         partyIDs,
			Threshold:        N - 1,
			Group:            group,
		}
		//The Start function is called to start the protocol round,
		r, err := Start(info, pl, nil, true)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		//the returned session r is appended to the rounds slice.
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}
	//the checkOutput function is called to verify the output of the protocol rounds
	checkOutput(t, rounds)
}

func TestRefresh(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := 4
	T := N - 1
	configs, _ := test.GenerateConfig(group, N, T, mrand.New(mrand.NewSource(1)), pl)

	rounds := make([]round.Session, 0, N)
	for _, c := range configs {
		info := round.Info{
			ProtocolID:       "cmp/refresh-test",
			FinalRoundNumber: Rounds,
			SelfID:           c.ID,
			PartyIDs:         c.PartyIDs(),
			Threshold:        N - 1,
			Group:            group,
		}
		//The Start function is called to start the protocol round,
		r, err := Start(info, pl, c, true)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		//the returned session r is appended to the rounds slice.
		rounds = append(rounds, r)
	}
	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}
	//the checkOutput function is called to verify the output of the protocol rounds
	checkOutput(t, rounds)
}
