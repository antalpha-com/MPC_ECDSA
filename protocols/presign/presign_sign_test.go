package presign

import (
	mrand "math/rand"
	"testing"

	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/test"
	"MPC_ECDSA/pkg/ecdsa"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pool"
	"MPC_ECDSA/protocols/config"

	"MPC_ECDSA/pkg/BigInt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

var (
	oneNat      = new(BigInt.Nat).SetUint64(1)
	oneInt      = new(BigInt.Nat).SetNat(oneNat)
	minusOneInt = new(BigInt.Nat).SetNat(oneNat).Neg(1)

	N           = 4
	T           = N - 1
	group       = curve.Secp256k1{}
	configs     map[party.ID]*config.Config
	partyIDs    party.IDSlice
	messageHash []byte
)

// init function initializes the package by generating configurations, deriving BIP32 keys, and computing the message hash for the test case.
func init() {
	//create a new random source
	source := mrand.New(mrand.NewSource(1))
	pl := pool.NewPool(0)
	defer pl.TearDown()
	//generate configurations and party IDs
	configs, partyIDs = test.GenerateConfig(group, N, T, source, pl)
	for id, c := range configs {
		configs[id], _ = c.DeriveBIP32(0)
	}
	//compute the SHA3-256 hash of the string "hello" and stores the result in messageHash using sha3.ShakeSum128.
	messageHash = make([]byte, 64)
	sha3.ShakeSum128(messageHash, []byte("hello"))
}

// The TestRound function is a test function that tests the execution of a presigning protocol round.
func TestRound(t *testing.T) {
	//iterate over each configuration in the configs list
	rounds := make([]round.Session, 0, N)
	for _, c := range configs {
		pl := pool.NewPool(1)
		defer pl.TearDown()
		//start the presigning protocol
		r, err := StartPresign(c, partyIDs, messageHash, pl)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}
	//enter a loop to process the rounds until they are completed.
	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}
	for _, r := range rounds {
		assert.IsType(t, &round.Output{}, r)
		signature, ok := r.(*round.Output).Result.(*ecdsa.Signature)
		assert.True(t, ok, "result should *ecdsa.Signature")
		assert.True(t, signature.Verify(configs[r.SelfID()].PublicPoint(), messageHash))
	}
}
