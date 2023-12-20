package presign

import (
	"testing"

	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/test"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pool"

	"MPC_ECDSA/pkg/BigInt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestRule struct {
	BeforeFinalize func(rBefore round.Session)
	AfterFinalize  func(rNext round.Session)
	BeforeSend     func(rNext round.Session, to party.ID, content round.Content)
}

func (tr *TestRule) ModifyBefore(rBefore round.Session) {
	if rBefore.SelfID() != "a" {
		return
	}
	if tr.BeforeFinalize != nil {
		tr.BeforeFinalize(rBefore)
	}
}

func (tr *TestRule) ModifyAfter(rNext round.Session) {
	if rNext.SelfID() != "a" {
		return
	}
	if tr.AfterFinalize != nil {
		tr.AfterFinalize(rNext)
	}
}

func (tr *TestRule) ModifyContent(rNext round.Session, to party.ID, content round.Content) {
	if rNext.SelfID() != "a" {
		return
	}
	if tr.BeforeSend != nil {
		tr.BeforeSend(rNext, to, content)
	}
}

// The TestRoundFail function performs a series of tests for different failure scenarios in the protocol round
func TestRoundFail(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	//Each test case within the tests slice defines a specific modification to the TestRule struct.
	tests := []struct {
		name string
		r    TestRule
	}{
		{
			"round 3 sub one from delta share",
			TestRule{
				AfterFinalize: func(rNext round.Session) {
					if r, ok := rNext.(*presign4); ok {
						oneScalar := r.Group().NewScalar().SetNat(oneNat)
						r.DeltaShares[r.SelfID()] = r.Group().NewScalar().Set(r.DeltaShares[r.SelfID()]).Sub(oneScalar)
					}
				},
				BeforeSend: func(rNext round.Session, to party.ID, content round.Content) {
					r, okR := rNext.(*presign4)
					c, okC := content.(*broadcast4)
					if okR || okC {
						oneScalar := r.Group().NewScalar().SetNat(oneNat)
						c.DeltaShare = r.Group().NewScalar().Set(c.DeltaShare).Sub(oneScalar)
					}
				},
			},
		},
		{
			"round 3 modify gamma for delta",
			TestRule{
				BeforeFinalize: func(rPrevious round.Session) {
					if r, ok := rPrevious.(*presign3); ok {
						r.GammaShare = new(BigInt.Nat).Add(r.GammaShare, minusOneInt, -1)
					}
				},
				AfterFinalize: func(rNext round.Session) {
					if r, ok := rNext.(*presign4); ok {
						r.GammaShare = new(BigInt.Nat).Add(r.GammaShare, oneInt, -1)
					}
				},
			},
		},
		{
			"round 3 modify x to change chi",
			TestRule{
				BeforeFinalize: func(rPrevious round.Session) {
					switch r := rPrevious.(type) {
					case *presign3:
						minusOne := r.Group().NewScalar().SetNat(oneNat).Negate()
						r.SecretECDSA = minusOne.Add(r.SecretECDSA)
					default:
					}
				},
				AfterFinalize: func(rNext round.Session) {
					switch r := rNext.(type) {
					case *presign4:
						one := r.Group().NewScalar().SetNat(oneNat)
						r.SecretECDSA = one.Add(r.SecretECDSA)
					default:
					}
				},
			},
		},
		{
			"round 3 modify chi force abort",
			TestRule{
				AfterFinalize: func(rNext round.Session) {
					if r, ok := rNext.(*presign3); ok {
						r.SecretECDSA = r.Group().NewScalar().SetNat(oneNat).Add(r.SecretECDSA)
					}
				},
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			rounds := make([]round.Session, 0, N)
			for _, c := range configs {
				//StartPresign function is called to initialize the round sessions
				r, err := StartPresign(c, partyIDs, messageHash[:], pl)(nil)
				require.NoError(t, err)
				rounds = append(rounds, r)
			}
			for {
				err, done := test.Rounds(rounds, &testCase.r)
				if err != nil || done {
					if err != nil {
						t.Log(err)
					}
					assert.Error(t, err, "round should terminate with error")
					break
				}
			}
		})
	}
}
