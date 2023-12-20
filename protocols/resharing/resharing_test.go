// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"MPC_ECDSA/internal/test"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	"fmt"
	"testing"
)

var group = curve.Secp256k1{}

func ResetOK(NewpartyIDs []party.ID, OldpartyIDs []party.ID, oldOK map[party.ID]bool, newOK map[party.ID]bool) {
	for _, j := range OldpartyIDs {
		oldOK[j] = false
	}
	for _, j := range NewpartyIDs {
		newOK[j] = false
	}
}
func TestResetOK(t *testing.T) {
	NewpartyIDs := test.PartyIDs(3)
	OldpartyIDs := test.ResharingPartyIDs(4)
	oldOK := make(map[party.ID]bool, len(OldpartyIDs))
	newOK := make(map[party.ID]bool, len(NewpartyIDs))
	ResetOK(NewpartyIDs, OldpartyIDs, oldOK, newOK)
	fmt.Println("oldOK:", oldOK)
	fmt.Println("newOK:", newOK)
}
func RemoveDuplicates(arr []party.ID) []party.ID {
	unique := make(map[party.ID]bool)
	result := []party.ID{}

	for _, value := range arr {
		if !unique[value] {
			unique[value] = true
			result = append(result, value)
		}
	}
	return result
}

func TestRemoveDuplicatesg(t *testing.T) {
	var NewParties = []party.ID{"1", "2", "3"}
	var OldParties = []party.ID{"1", "2", "3", "4"}

	Parties := append(NewParties, OldParties...)
	fmt.Println("before:", Parties)
	Parties = RemoveDuplicates(Parties)
	fmt.Println("after:", Parties)
}

//To prevent circular references, we put the test function of Resharing in internal/save/fixture_test.go.

//func TestResharing(t *testing.T) {
//	pl := pool.NewPool(0)
//	defer pl.TearDown()
//
//	//load local keygen results
//	KeyGenResultsInterface, err := save.LoadLocalKeyGenResults()
//	if err != nil {
//		t.Fatal(err)
//	}
//	KeyGenResults := make(map[party.ID]*config.Config, len(KeyGenResultsInterface))
//	var OldpartyIDs []party.ID
//	for j, v := range KeyGenResultsInterface {
//		if config, ok := v.(*config.Config); ok {
//			KeyGenResults[j] = config
//			OldpartyIDs = append(OldpartyIDs, j)
//		} else {
//			log.Info("Conversion to *config.Config failed")
//		}
//	}
//	OldCount := len(KeyGenResultsInterface)
//	NewThreshold := 3
//	NewCount := NewThreshold + 1
//	N := NewCount + OldCount
//	partyIDs := make([]party.ID, 0, N)
//	NewpartyIDs := test.ResharingPartyIDs(NewCount)
//	partyIDs = append(OldpartyIDs, NewpartyIDs...)
//	OldCommittee := make(map[party.ID]bool, len(partyIDs))
//	NewCommittee := make(map[party.ID]bool, len(partyIDs))
//	for _, partyid := range partyIDs {
//		OldCommittee[partyid] = false
//		NewCommittee[partyid] = false
//	}
//	rounds := make([]round.Session, 0, N)
//	for _, newpartyid := range NewpartyIDs {
//		NewCommittee[newpartyid] = true
//	}
//	for _, oldpartyid := range OldpartyIDs {
//		OldCommittee[oldpartyid] = true
//	}
//	var c interface{}
//	//remove duplicates
//	partyIDs = RemoveDuplicates(partyIDs)
//	for _, partyID := range partyIDs {
//		if OldCommittee[partyID] {
//			c = KeyGenResultsInterface[partyID]
//		} else {
//			c = nil
//		}
//		info := round.Info{
//			ProtocolID:       "cmp/resharing-test",
//			FinalRoundNumber: Rounds,
//			SelfID:           partyID,
//			PartyIDs:         partyIDs,
//			Threshold:        OldCount - 1,
//			Group:            group,
//			KeyGenConfig:     c,
//			NewPartyIDs:      NewpartyIDs,
//			OldPartyIDs:      OldpartyIDs,
//			NewThreshold:     NewThreshold,
//			IsNewCommittee:   NewCommittee[partyID],
//			IsOldCommittee:   OldCommittee[partyID],
//			OldOK:            make(map[party.ID]bool, len(OldpartyIDs)),
//			NewOK:            make(map[party.ID]bool, len(NewpartyIDs)),
//		}
//		//The Start function is called to start the protocol round,
//		r, err := Start(info, pl)(nil)
//		require.NoError(t, err, "round creation should not result in an error")
//		//the returned session r is appended to the rounds slice.
//		rounds = append(rounds, r)
//	}
//	println("finish start")
//	for {
//		err, done := test.RoundsResharing(rounds, nil)
//		require.NoError(t, err, "failed to process round")
//		if done {
//			break
//		}
//	}
//	//the checkOutput function is called to verify the output of the protocol rounds
//	checkOutput(t, rounds, NewCommittee)
//}
//func checkOutput(t *testing.T, rounds []round.Session, NewCommittee map[party.ID]bool) {
//	N := len(rounds)
//	//create an empty slice newConfigs to store the unmarshalled configurations.
//	newConfigs := make([]*config.Config, 0, N)
//	//For each round in the rounds slice, it verifies that the round is of type round.Output
//	for _, r := range rounds {
//		id := r.SelfID()
//		if NewCommittee[id] {
//			require.IsType(t, &round.Output{}, r)
//			resultRound := r.(*round.Output)
//			require.IsType(t, &config.Config{}, resultRound.Result)
//			c := resultRound.Result.(*config.Config)
//			marshalledConfig, err := cbor.Marshal(c)
//			require.NoError(t, err)
//			unmarshalledConfig := config.EmptyConfig(group)
//			err = cbor.Unmarshal(marshalledConfig, unmarshalledConfig)
//			require.NoError(t, err)
//			newConfigs = append(newConfigs, unmarshalledConfig)
//		} else {
//			continue
//		}
//	}
//	firstConfig := newConfigs[0]
//	pk := firstConfig.PublicPoint()
//	for _, c := range newConfigs {
//		//println("public长度：", len(firstConfig.Public))
//		for id, p := range firstConfig.Public {
//			assert.True(t, p.ECDSA.Equal(c.Public[id].ECDSA), "ecdsa not the same", id)
//			assert.True(t, p.ElGamal.Equal(c.Public[id].ElGamal), "elgamal not the same", id)
//			assert.True(t, p.Paillier.Equal(c.Public[id].Paillier), "paillier not the same", id)
//			assert.True(t, p.Pedersen.S().Eq(c.Public[id].Pedersen.S()) == 1, "S not the same", id)
//			assert.True(t, p.Pedersen.T().Eq(c.Public[id].Pedersen.T()) == 1, "T not the same", id)
//			assert.True(t, p.Pedersen.N().Nat().Eq(c.Public[id].Pedersen.N().Nat()) == 1, "N not the same", id)
//		}
//		assert.True(t, pk.Equal(c.PublicPoint()), "RID is different")
//		assert.Equal(t, firstConfig.RID, c.RID, "RID is different")
//		assert.EqualValues(t, firstConfig.ChainKey, c.ChainKey, "ChainKey is different")
//		data, err := c.MarshalBinary()
//		assert.NoError(t, err, "failed to marshal new config", c.ID)
//		c2 := config.EmptyConfig(group)
//		err = c2.UnmarshalBinary(data)
//		assert.NoError(t, err, "failed to unmarshal new config", c.ID)
//	}
//}
