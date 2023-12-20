// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"MPC_ECDSA/internal/round"
	sch "MPC_ECDSA/pkg/zk/sch"
	"MPC_ECDSA/protocols/config"
	"errors"
	log "github.com/sirupsen/logrus"
)

type broadcastToNewParty5 struct {
	//round.NormalBroadcastContent
	// SchnorrResponse is the Schnorr proof of knowledge of the new secret share
	SchnorrResponse *sch.Response
}

func (b broadcastToNewParty5) RoundNumber() round.Number {

	return 7
}

// VerifyMessage implements round.Round.
func (r *round7) VerifyMessage(msg round.Message) error {
	log.Info(r.Info.SelfID, " initiates round 7 VerifyMessage ")

	//Retrieve the sender of the message.
	from := msg.From
	//Retrieve the body of the message and check if it is of type *broadcast5.
	body, ok := msg.Content.(*broadcastToNewParty5)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	// Check if the Schnorr response in the message is valid
	if !body.SchnorrResponse.IsValid() {
		return round.ErrNilFields
	}
	if !body.SchnorrResponse.Verify(r.HashForID(from),
		r.UpdatedConfig.Public[from].ECDSA,
		r.SchnorrCommitments[from], nil) {
		return errors.New("failed to validate schnorr proof for received share")
	}
	r.Info.NewOK[from] = true
	return nil
}

// Finalize implements round.Round.
func (r *round7) Finalize(chan<- *round.Message) (round.Session, error) {
	log.Info(r.Info.SelfID, " initiates round7 Finalize")
	if !r.CheckOK() {
		err := errors.New("not all OK")
		return r, err
	}
	if r.Info.IsNewCommittee {
		log.Info(r.Info.SelfID, " new party return result round")
		return r.ResultRound(r.UpdatedConfig), nil
	} else {
		r.UpdatedConfig = nil
		log.Info(r.Info.SelfID, " old party return result round")
		return r.ResultRound(r.UpdatedConfig), nil
	}
}

type round7 struct {
	*round6
	UpdatedConfig *config.Config
}

func (r *round7) StoreMessage(msg round.Message) error {
	log.Info(r.Info.SelfID, " initiates round 7 StoreMessage ")
	return nil
}

// Number implements round.Round.
func (round7) Number() round.Number { return 7 }

func (r *round7) MessageContent() round.Content {
	return &broadcastToNewParty5{
		SchnorrResponse: sch.EmptyResponse(r.Group()),
	}
}
