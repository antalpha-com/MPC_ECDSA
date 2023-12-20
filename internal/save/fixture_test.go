// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package save

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/test"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pool"
	"MPC_ECDSA/protocols/config"
	"MPC_ECDSA/protocols/keygen"
	"MPC_ECDSA/protocols/resharing"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	testFixtureDirFormat  = "%s/../../test/local_test_fixture/local_mickey"
	testFixtureFileFormat = "result.data"
)

var group = curve.Secp256k1{}

type MickeyMouse struct {
	Test1 string
	Test2 string
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

// TestResharing test resharing protocol.
// our test resharing protocol can complete the resharing of (t, n) changes
func TestResharing(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	//load local keygen results
	KeyGenResultsInterface, err := LoadLocalKeyGenResults()
	if err != nil {
		t.Fatal(err)
	}
	KeyGenResults := make(map[party.ID]*config.Config, len(KeyGenResultsInterface))
	var OldpartyIDs []party.ID
	//Get the id of each old participant and the key generation result from the local test results
	for j, v := range KeyGenResultsInterface {
		//convert the interface type to *config.Config type
		if config, ok := v.(*config.Config); ok {
			KeyGenResults[j] = config
			OldpartyIDs = append(OldpartyIDs, j)
		} else {
			log.Info("Conversion to *config.Config failed")
		}
	}
	OldCount := len(KeyGenResultsInterface)
	//Set the new threshold and the number of new participants
	NewThreshold := 3
	NewCount := NewThreshold + 1
	N := NewCount + OldCount
	partyIDs := make([]party.ID, 0, N)

	//Generate new participants
	NewpartyIDs := test.ResharingPartyIDs(NewCount)

	//Merge new participants and old participants into one array partyIDs
	partyIDs = append(OldpartyIDs, NewpartyIDs...)
	OldCommittee := make(map[party.ID]bool, len(partyIDs))
	NewCommittee := make(map[party.ID]bool, len(partyIDs))
	for _, partyid := range partyIDs {
		OldCommittee[partyid] = false
		NewCommittee[partyid] = false
	}
	rounds := make([]round.Session, 0, N)

	//set the new and old member tags of the participants.
	//If it is a new participant, NewCommittee[partyID] is true, otherwise it is false. If it is an old participant, OldCommittee[partyID] is true, otherwise it is false.

	for _, newpartyid := range NewpartyIDs {
		NewCommittee[newpartyid] = true
	}
	for _, oldpartyid := range OldpartyIDs {
		OldCommittee[oldpartyid] = true
	}
	var c interface{}
	//remove duplicates
	//if partyIDs has duplicate members, that is, the participant is both a new member and an old member, then keep only one
	partyIDs = RemoveDuplicates(partyIDs)
	//for each participant, create a round.Info object and a round.Session object, and store them in the rounds slice.
	for _, partyID := range partyIDs {
		//If the participant is an old member, the key generation result is used as the input of the resharing protocol, otherwise nil is used as the input.
		if OldCommittee[partyID] {
			c = KeyGenResultsInterface[partyID]
		} else {
			c = nil
		}
		info := round.Info{
			ProtocolID:       "cmp/resharing-test",
			FinalRoundNumber: 7,
			SelfID:           partyID,
			PartyIDs:         partyIDs,
			Threshold:        OldCount - 1,
			Group:            group,
			KeyGenConfig:     c,
			NewPartyIDs:      NewpartyIDs,
			OldPartyIDs:      OldpartyIDs,
			NewThreshold:     NewThreshold,
			IsNewCommittee:   NewCommittee[partyID],
			IsOldCommittee:   OldCommittee[partyID],
			OldOK:            make(map[party.ID]bool, len(OldpartyIDs)),
			NewOK:            make(map[party.ID]bool, len(NewpartyIDs)),
		}
		//The Start function is called to start the protocol round,
		r, err := resharing.Start(info, pl)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		//the returned session r is appended to the rounds slice.
		rounds = append(rounds, r)
	}
	log.Info("all parties have finished Start")
	for {
		err, done := test.RoundsResharing(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}
	log.Info("all parties have finished test.RoundsResharing")
	//the checkOutput function is called to verify the output of the protocol rounds
	ResharingcheckOutput(t, rounds, NewCommittee)
	log.Info(" successfully resharing ")
}
func ResharingcheckOutput(t *testing.T, rounds []round.Session, NewCommittee map[party.ID]bool) {
	N := len(rounds)
	//create an empty slice newConfigs to store the unmarshalled configurations.
	newConfigs := make([]*config.Config, 0, N)
	//For each round in the rounds slice, it verifies that the round is of type round.Output
	for _, r := range rounds {
		id := r.SelfID()
		if NewCommittee[id] {
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
		} else {
			continue
		}
	}
	firstConfig := newConfigs[0]
	pk := firstConfig.PublicPoint()
	for _, c := range newConfigs {
		for id, p := range firstConfig.Public {
			assert.True(t, p.ECDSA.Equal(c.Public[id].ECDSA), "ecdsa not the same", id)
			assert.True(t, p.ElGamal.Equal(c.Public[id].ElGamal), "elgamal not the same", id)
			assert.True(t, p.Paillier.Equal(c.Public[id].Paillier), "paillier not the same", id)
			assert.True(t, p.Pedersen.S().Eq(c.Public[id].Pedersen.S()) == 1, "S not the same", id)
			assert.True(t, p.Pedersen.T().Eq(c.Public[id].Pedersen.T()) == 1, "T not the same", id)
			assert.True(t, p.Pedersen.N().Nat().Eq(c.Public[id].Pedersen.N().Nat()) == 1, "N not the same", id)
		}
		assert.True(t, pk.Equal(c.PublicPoint()), "RID is different")
		assert.Equal(t, firstConfig.RID, c.RID, "RID is different")
		assert.EqualValues(t, firstConfig.ChainKey, c.ChainKey, "ChainKey is different")
		data, err := c.MarshalBinary()
		assert.NoError(t, err, "failed to marshal new config", c.ID)
		c2 := config.EmptyConfig(group)
		err = c2.UnmarshalBinary(data)
		assert.NoError(t, err, "failed to unmarshal new config", c.ID)
	}
}

// TestKeygenAndSave test keygen protocol and save every result to test/local_test_fixture/local_keygen
func TestKeygenAndSave(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := 4
	T := N - 1

	partyIDs := test.PartyIDs(N)

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		info := round.Info{
			ProtocolID:       "cmp/keygen-test",
			FinalRoundNumber: keygen.Rounds,
			SelfID:           partyID,
			PartyIDs:         partyIDs,
			Threshold:        T,
			Group:            group,
		}
		//The Start function is called to start the protocol round,
		r, err := keygen.Start(info, pl, nil, true)(nil)
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
	// clear dir
	TestClearFixtureFiles(t)

	// save every result to test/local_test_fixture/local_keygen
	for _, r := range rounds {
		resultRound := r.(*round.Output)
		c := resultRound.Result.(*config.Config)
		err := SaveLocalKeyGenResult(c, string(c.ID))
		require.NoError(t, err, "failed to save config")
	}
}

// TestLoadLocalKeyGenResults test load local keygen results
func TestLoadLocalKeyGenResults(t *testing.T) {
	Chdir()
	// load every result from test/local_test_fixture/local_keygen
	results, err := LoadLocalKeyGenResults()
	require.NoError(t, err, "failed to load config")
	for _, result := range results {
		t.Logf("result: %+v", result)
	}
}

// TestLoadLocalKeyGenResultWithID test load local keygen result with id
func TestLoadLocalKeyGenResultWithID(t *testing.T) {
	Chdir()
	// load every result from test/local_test_fixture/local_keygen
	result, err := LoadLocalKeyGenResultWithID("a")
	require.NoError(t, err, "failed to load config")
	t.Logf("result: %+v", result)
}

func Chdir() (err error) {
	err = os.Chdir("../")
	return
}

// test WriteFixtureFile function
func TestWriteFixtureFile(t *testing.T) {
	Chdir()
	// create a test struct
	testStruct := &MickeyMouse{
		Test1: "test 115",
		Test2: "test 222",
	}
	data, _ := cbor.Marshal(testStruct)
	// write the save file
	err := WriteFixtureFile(data, "testStage", "", testFixtureDirFormat, testFixtureFileFormat)
	if err != nil {
		t.Errorf("unable to write save file: %v", err)
	}
}

// test ReadFixtureFile function
func TestReadFixtureFile(t *testing.T) {
	Chdir()
	// read the save file
	//testStruct, err := ReadFixtureFile()
	//mouse := testStruct.(*MickeyMouse)
	result, err := ReadFixtureFile("testStage", "", testFixtureDirFormat, testFixtureFileFormat)
	if err != nil {
		t.Errorf("unable to read save file: %v", err)
	}
	var mouse MickeyMouse
	err = cbor.Unmarshal(result, &mouse)
	if err != nil {
		t.Errorf("unable to unmarshal save data for save file")
	}
	// print the result
	t.Logf("testStruct: %+v", mouse)
}

// test LoadPresign3Result function
func TestLoadPresign3Result(t *testing.T) {
	Chdir()
	// read the save file
	// please run this test after TestKeygenAndSave
	result, err := LoadPresign3Result("【ID_TO_BE_ADD】")
	if err != nil {
		t.Errorf("unable to read save file: %v", err)
	}
	// print the result
	t.Logf("testStruct: %+v", result)
}

// test DeleteFixtureFile function
func TestDeleteFixtureFile(t *testing.T) {
	Chdir()
	// delete the save file
	err := DeleteFixtureFile("testStage", "", testFixtureDirFormat, testFixtureFileFormat)
	if err != nil {
		t.Errorf("unable to delete save file: %v", err)
	}
}

// test ClearFixtureFiles function
//
//	func TestClearFixtureFiles(t *testing.T) {
//		Chdir()
//		// clear the save files
//		err := ClearFixtureFiles(LocalKeygenFixtureDirFormat)
//		if err != nil {
//			t.Errorf("unable to clear save files: %v", err)
//		}
//	}
//
// test ClearFixtureFiles function
//
//	func TestClearFixtureFiles(t *testing.T) {
//		Chdir()
//		_, callerFileName, _, _ := runtime.Caller(0)
//		srcDirName := filepath.Dir(callerFileName)
//		fixtureDirName := fmt.Sprintf(LocalKeygenFixtureDirFormat, srcDirName)
//		println(fixtureDirName)
//		// clear the save files
//		err := ClearFixtureFiles(fixtureDirName)
//		//err := ClearFixtureFiles(LocalKeygenFixtureDirFormat)
//		if err != nil {
//			t.Errorf("unable to clear save files: %v", err)
//		}
//	}
//
// test ClearFixtureFiles function
func TestClearFixtureFiles(t *testing.T) {
	Chdir()
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	directoryPath := fmt.Sprintf(LocalKeygenFixtureDirFormat, srcDirName)
	fmt.Println("clear path is ", directoryPath)

	// clear the save files
	err := filepath.Walk(directoryPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return err
		}

		if !info.IsDir() {
			err := os.Remove(path)
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Printf("delete：%s\n", path)
			}
		}

		return nil
	})

	require.NoError(t, err)
}

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
