// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package protocols

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/test"
	"MPC_ECDSA/pkg/ecdsa"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pool"
	"MPC_ECDSA/protocols/config"
	"MPC_ECDSA/protocols/keygen"
	"MPC_ECDSA/protocols/presign"
	"MPC_ECDSA/protocols/sign"
	mrand "math/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

// global variables to test all stages
var (
	N           = 4                         // number of parties
	T           = N - 1                     // threshold
	group       = curve.Secp256k1{}         // the curve
	configs     map[party.ID]*config.Config // map from party ID to config
	partyIDs    party.IDSlice               // partyID
	messageHash []byte                      // message to sign
)

// checkKeygenOutput used to check whether the keygen stage and refresh stage output is valid.
func checkKeygenOutput(t *testing.T, rounds []round.Session) {
	N := len(rounds)
	newConfigs := make([]*config.Config, 0, N)
	// type check
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
	// Consistency check
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

// checkSignOutput used to check whether the preSign and sign stage and sign stage output is valid.
func checkSignOutput(t *testing.T, rounds []round.Session) {
	for _, r := range rounds {
		assert.IsType(t, &round.Output{}, r)
		signature, ok := r.(*round.Output).Result.(*ecdsa.Signature)
		assert.True(t, ok, "result should *ecdsa.Signature")
		assert.True(t, signature.Verify(configs[r.SelfID()].PublicPoint(), messageHash))
	}
}

// TestAllStage is used to test all stages one by one
// Normal tls communication is replaced by the channel method provided in test package to simulate multiple parties
func TestAllStage(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// generate party ids
	partyIDs = test.PartyIDs(N)

	// 1. test keygen
	t.Log("test keygen stage")

	// generate session
	keygenRounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		info := round.Info{
			ProtocolID:       "MPC_ECDSA/keygen-test",
			FinalRoundNumber: keygen.Rounds,
			SelfID:           partyID,
			PartyIDs:         partyIDs,
			Threshold:        T,
			Group:            group,
		}
		r, err := keygen.Start(info, pl, nil, true)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		keygenRounds = append(keygenRounds, r)
	}
	// loop to simulate rounds‘ rotation
	for {
		err, done := test.Rounds(keygenRounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}
	// check if output is valid
	checkKeygenOutput(t, keygenRounds)

	// 2. test refresh
	t.Log("test refresh stage")
	// Generate keygen's result config
	configs, _ = test.GenerateConfig(group, N, T, mrand.New(mrand.NewSource(1)), pl)
	// generate session
	refreshRounds := make([]round.Session, 0, N)
	for _, c := range configs {
		info := round.Info{
			ProtocolID:       "MPC_ECDSA/refresh-test",
			FinalRoundNumber: keygen.Rounds,
			SelfID:           c.ID,
			PartyIDs:         c.PartyIDs(),
			Threshold:        N - 1,
			Group:            group,
		}
		r, err := keygen.Start(info, pl, c, true)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		refreshRounds = append(refreshRounds, r)
	}
	// loop to simulate rounds‘ rotation
	for {
		err, done := test.Rounds(refreshRounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}
	// check if output is valid
	checkKeygenOutput(t, refreshRounds)

	// 3. presign and sign
	t.Log("test presign and sign stage")
	// init message to sign
	messageHash = make([]byte, 64)
	sha3.ShakeSum128(messageHash, []byte("hello"))
	// generate session
	presignAndSignRounds := make([]round.Session, 0, N)
	for _, c := range configs {
		pl := pool.NewPool(1)
		defer pl.TearDown()
		r, err := presign.StartPresign(c, partyIDs, messageHash, pl)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		presignAndSignRounds = append(presignAndSignRounds, r)
	}
	// loop to simulate rounds‘ rotation
	for {
		err, done := test.Rounds(presignAndSignRounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}
	// check if output is valid
	checkSignOutput(t, presignAndSignRounds)

	// 4. sign
	t.Log("test sign stage")
	// generate session
	signRounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		c := configs[partyID]
		r, err := sign.StartSign(c, partyIDs, messageHash, pl)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		signRounds = append(signRounds, r)
	}
	// loop to simulate rounds‘ rotation
	for {
		err, done := test.Rounds(signRounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}
	// check if output is valid
	checkSignOutput(t, signRounds)
}
