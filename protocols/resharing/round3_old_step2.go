// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/types"
	"MPC_ECDSA/pkg/BigInt"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/polynomial"
	"MPC_ECDSA/pkg/party"
	zksch "MPC_ECDSA/pkg/zk/sch"
	"errors"
	log "github.com/sirupsen/logrus"
)

type round3 struct {
	//By embedding round1, the round2 struct inherits all the fields and methods defined in round1
	*round2

	// VSSPolynomials[j] = Fⱼ(X) = fⱼ(X)•G
	VSSPolynomials map[party.ID]*polynomial.Exponent

	// Commitments[j] = H(Keygen3ⱼ ∥ Decommitments[j])
	Commitments map[party.ID]hash.Commitment

	// RIDs[j] = ridⱼ
	RIDs map[party.ID]types.RID
	// ChainKeys[j] = cⱼ
	ChainKeys map[party.ID]types.RID

	// ShareReceived[j] = xʲᵢ
	// share received from party j
	ShareReceived map[party.ID]curve.Scalar

	ElGamalPublic map[party.ID]curve.Point
	// PaillierPublic[j] = Nⱼ
	PaillierPublic map[party.ID]*paillier.PublicKey

	// NModulus[j] = Nⱼ
	NModulus map[party.ID]*BigInt.Nat
	// S[j], T[j] = sⱼ, tⱼ
	S, T map[party.ID]*BigInt.Nat

	ElGamalSecret curve.Scalar

	// PaillierSecret = (pᵢ, qᵢ)
	PaillierSecret *paillier.SecretKey

	// PedersenSecret = λᵢ
	// Used to generate the Pedersen parameters
	PedersenSecret *BigInt.Nat

	// SchnorrRand = aᵢ
	// Randomness used to compute Schnorr commitment of proof of knowledge of secret share
	SchnorrRand *zksch.Randomness

	// Decommitment for Keygen3ᵢ
	Decommitment hash.Decommitment // uᵢ
}
type broadcastToNewParty2 struct {
	Commitment hash.Commitment
}

func (b broadcastToNewParty2) RoundNumber() round.Number {
	return 3
}

// - save commitment Vⱼ.
func (r *round3) StoreMessage(msg round.Message) error {
	log.Info(r.Info.SelfID, " initiates round3 StoreMessage")
	if r.Info.IsNewCommittee {
		body, _ := msg.Content.(*broadcastToNewParty2)
		r.Commitments[msg.From] = body.Commitment
		r.Info.NewOK[msg.From] = true
		return nil
	} else {
		return nil
	}
}

// VerifyMessage implements round.Round.
// new party verifies the message sent by new party in round2
func (r *round3) VerifyMessage(msg round.Message) error {
	log.Info(r.Info.SelfID, " initiates round3 VerifyMessage")
	if r.Info.IsNewCommittee {
		body, ok := msg.Content.(*broadcastToNewParty2)
		if !ok || body == nil {
			return round.ErrInvalidContent
		}
		if err := body.Commitment.Validate(); err != nil {
			log.Errorln("fail to validate commit")
			return err
		}
		return nil
	} else {
		return nil
	}
}

// check if all old parties have store the message from the previous round
func (r *round3) CheckOK() bool {
	if r.Info.IsNewCommittee {
		for _, j := range r.Info.OldPartyIDs {
			if !r.Info.OldOK[j] {
				return false
			}
		}
	}
	return true
}

// Finalize function is used to execute the 3th round of the key resharing protocol. New parties return directly to the next round, and Old parties execute this round.
func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
	log.Info(r.Info.SelfID, " initiates round3 Finalize")
	//check whether it has already processed (verified + stored) messages from the previous round.
	if !r.CheckOK() {
		err := errors.New("not all OK")
		return r, err
	}
	//reset all the OK flags to false
	r.resetOK()
	//reset the "newOK" flag to true.
	r.allNewOK()
	//now all the newok are true, and all the oldok are false.
	//Because the message of this round is sent by the old party, so all the oldok are false, only when the message of this round is successfully stored, the corresponding oldok will be set to true.
	if !r.Info.IsOldCommittee { //new
		nextRound := &round4{
			round3: r,
		}
		return nextRound, nil
	} else { //old  ,old and new
		for _, j := range r.Info.NewPartyIDs {
			if j == r.SelfID() {
				continue
			}
			//send share ,commitment,decommitment to new party
			err := r.SendMessage(out, &messageToNewParty3{
				ShareOldParty:          r.SharesOldParty[j],
				DeCommitmentsOldParty:  r.SelfDecommitmentOldParty,
				VSSPolynomialsOldParty: r.VSSPolynomialsOldParty[r.SelfID()],
			}, j)
			if err != nil {
				return r, err
			}
		}
		nextRound := &round4{
			round3: r,
		}
		return nextRound, nil

	}
}

// MessageContent implements round.Round.
func (r *round3) MessageContent() round.Content {
	if r.Info.IsNewCommittee {
		return &broadcastToNewParty2{}
	} else {
		//return &broadcastToOldPartyRound2{}
		return nil
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
