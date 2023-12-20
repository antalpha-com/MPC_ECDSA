// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presign3rounds

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/types"
	"MPC_ECDSA/pkg/ecdsa3rounds"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/polynomial"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pedersen"
	"MPC_ECDSA/pkg/pool"
	"MPC_ECDSA/pkg/protocol"
	"MPC_ECDSA/protocols/config"
	"errors"
	"fmt"
)

const (
	protocolOfflineID                  = "cmp/presign-offline"
	protocolOnlineID                   = "cmp/presign-online"
	protocolFullID                     = "cmp/presign-full"
	protocolOfflineRounds round.Number = 4
	protocolFullRounds    round.Number = 6
)

// StartPresign function returns a protocol.StartFunc for the Presign3 protocol.
func StartPresign(c *config.Config, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	//The returned StartFunc is a closure that takes a sessionID parameter of type []byte and returns a round.Session and an error.
	return func(sessionID []byte) (round.Session, error) {
		if c == nil {
			return nil, errors.New("presign3rounds: config is nil")
		}
		info := round.Info{
			SelfID:    c.ID,
			PartyIDs:  signers,
			Threshold: c.Threshold,
			Group:     c.Group,
		}
		//If the message length is zero, indicating no message, Perform offline pre-signing，the final round number is 7
		if len(message) == 0 {
			info.FinalRoundNumber = protocolOfflineRounds
			info.ProtocolID = protocolOfflineID
		} else { //exist message,  the full round number is 4
			info.FinalRoundNumber = protocolFullRounds
			info.ProtocolID = protocolFullID
		}
		// create session
		helper, err := round.NewSession(info, sessionID, pl, c, types.SigningMessage(message))
		if err != nil {
			return nil, fmt.Errorf("sign.Create: %w", err)
		}

		//check if the signers are a valid signing subset
		if !c.CanSign(helper.PartyIDs()) {
			return nil, errors.New("sign.Create: signers is not a valid signing subset")
		}

		// Scale public data
		T := helper.N() // the number of participants
		group := c.Group
		ECDSA := make(map[party.ID]curve.Point, T)
		ElGamal := make(map[party.ID]curve.Point, T)
		Paillier := make(map[party.ID]*paillier.PublicKey, T)
		Pedersen := make(map[party.ID]*pedersen.Parameters, T)
		PublicKey := group.NewPoint()
		//the lagrange coefficients generated using polynomial.Lagrange.
		lagrange := polynomial.Lagrange(group, signers)

		// Scale own secret
		//The own secret is scaled by multiplying the lagrange coefficient corresponding to the party ID with the ECDSA secret (c.ECDSA).
		SecretECDSA := group.NewScalar().Set(lagrange[c.ID]).Mul(c.ECDSA)
		for _, j := range helper.PartyIDs() {
			public := c.Public[j]
			// scale public key share
			ECDSA[j] = lagrange[j].Act(public.ECDSA)
			ElGamal[j] = public.ElGamal
			Paillier[j] = public.Paillier
			Pedersen[j] = public.Pedersen
			PublicKey = PublicKey.Add(ECDSA[j])
		}

		return &presign1{
			Helper:         helper,
			Pool:           pl,
			SecretECDSA:    SecretECDSA,
			SecretElGamal:  c.ElGamal,
			SecretPaillier: c.Paillier,
			PublicKey:      PublicKey,
			ECDSA:          ECDSA,
			ElGamal:        ElGamal,
			Paillier:       Paillier,
			Pedersen:       Pedersen,
			Message:        message,
		}, nil
	}
}

func StartPresignOnline(c *config.Config, signers []party.ID, preSignature *ecdsa3rounds.PreSignature3, message []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		if c == nil || preSignature == nil {
			return nil, errors.New("presign: config or preSignature is nil")
		}
		// this could be used to indicate a pre-signature later on
		// Check if the message is nil
		if len(message) == 0 {
			return nil, errors.New("sign.Create: message is nil")
		}
		// Validate the preSignature
		if err := preSignature.Validate(); err != nil {
			return nil, fmt.Errorf("sign.Create: %w", err)
		}
		// Get the signer IDs from the preSignature
		// Check if the signers are a valid signing subset according to the configuration
		if !c.CanSign(signers) {
			return nil, errors.New("sign.Create: signers is not a valid signing subset")
		}
		// Create a round.Info struct with the necessary information for the session
		info := round.Info{
			ProtocolID:       protocolOnlineID,
			FinalRoundNumber: protocolFullRounds,
			SelfID:           c.ID,
			PartyIDs:         signers,
			Threshold:        c.Threshold,
			Group:            c.Group,
		}
		// Create a new round.Session using round.NewSession
		helper, err := round.NewSession(
			info,
			sessionID,
			pl,
			c,
			hash.BytesWithDomain{
				TheDomain: "PreSignatureID",
				Bytes:     preSignature.ID,
			},
			types.SigningMessage(message),
		)
		if err != nil {
			return nil, fmt.Errorf("sign.Create: %w", err)
		}
		//Create and return a sign1 struct, which implements the round.Session interface
		return &sign1{
			Helper:       helper,
			PublicKey:    c.PublicPoint(),
			Message:      message,
			PreSignature: preSignature,
		}, nil
	}
}
