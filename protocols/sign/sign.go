package sign

import (
	"errors"
	"fmt"

	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/types"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/polynomial"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pedersen"
	"MPC_ECDSA/pkg/pool"
	"MPC_ECDSA/pkg/protocol"
	"MPC_ECDSA/protocols/config"
)

// protocolSignID for the "3 round" variant using echo broadcast.
const (
	protocolSignID                  = "cmp/sign"
	protocolSignRounds round.Number = 5
)

// StartSign function is a factory function that returns a closure of type protocol.StartFunc
// This closure is responsible for initializing and returning the initial round session for the signing protocol.
func StartSign(config *config.Config, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		group := config.Group
		//If the length of the message is zero, it means that there is no message to sign
		if len(message) == 0 {
			return nil, errors.New("sign.Create: message is nil")
		}
		//set up the basic information required for the round session
		info := round.Info{
			ProtocolID:       protocolSignID,
			FinalRoundNumber: protocolSignRounds,
			SelfID:           config.ID,
			PartyIDs:         signers,
			Threshold:        config.Threshold,
			Group:            config.Group,
		}
		//create a new round session helper
		helper, err := round.NewSession(info, sessionID, pl, config, types.SigningMessage(message))
		if err != nil {
			return nil, fmt.Errorf("sign.Create: %w", err)
		}
		//check whether the provided signers are a valid signing subset
		if !config.CanSign(helper.PartyIDs()) {
			return nil, errors.New("sign.Create: signers is not a valid signing subset")
		}

		// Scale public data
		T := helper.N()
		ECDSA := make(map[party.ID]curve.Point, T)
		Paillier := make(map[party.ID]*paillier.PublicKey, T)
		Pedersen := make(map[party.ID]*pedersen.Parameters, T)
		PublicKey := group.NewPoint()
		lagrange := polynomial.Lagrange(group, signers) // map of Lagrange coefficient id:l_i(0)
		// Scale own secret
		//The Lagrange coefficient of this party is multiplied by the private key l_i(0)*x_i
		SecretECDSA := group.NewScalar().Set(lagrange[config.ID]).Mul(config.ECDSA)
		SecretPaillier := config.Paillier
		for _, j := range helper.PartyIDs() {
			public := config.Public[j] // Public information of j (public key & parameters)
			// scale public key share
			ECDSA[j] = lagrange[j].Act(public.ECDSA) //Scalar multiplied by the point of the public key, returning a new point
			Paillier[j] = public.Paillier
			Pedersen[j] = public.Pedersen
			PublicKey = PublicKey.Add(ECDSA[j])
		}

		return &round1{
			Helper:         helper,
			PublicKey:      PublicKey,
			SecretECDSA:    SecretECDSA,
			SecretPaillier: SecretPaillier,
			Paillier:       Paillier,
			Pedersen:       Pedersen,
			ECDSA:          ECDSA,
			Message:        message,
		}, nil
	}
}
