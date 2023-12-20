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
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/party"
	zksch "MPC_ECDSA/pkg/zk/sch"
	"crypto/rand"
	"errors"
	log "github.com/sirupsen/logrus"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	//By embedding round1, the round2 struct inherits all the fields and methods defined in round1
	*round1
	SharesOldParty    map[party.ID]curve.Scalar
	VSSSecretOldParty *polynomial.Polynomial
	//// VSSPolynomials[j] = Fⱼ(X) = fⱼ(X)•G
	//
	SelfCommitmentOldParty hash.Commitment
	// Decommitment for Keygen3ᵢ
	SelfDecommitmentOldParty hash.Decommitment // uᵢ

	//// Commitments[j] = H(Keygen3ⱼ ∥ Decommitments[j])
	CommitmentsOldParty map[party.ID]hash.Commitment
	//// ShareReceived[j] = xʲᵢ
	//// share received from party j
	ShareReceivedOldParty map[party.ID]curve.Scalar
	// VSSPolynomials[j] = Fⱼ(X) = fⱼ(X)•G
	VSSPolynomialsOldParty map[party.ID]*polynomial.Exponent

	ECDSAOldParty curve.Point
}
type broadcastToNewParty1 struct {
	// Share = Encᵢ(x) is the encryption of the receivers share
	ECDSAOldParty      curve.Point
	CommitmentOldParty hash.Commitment
}

func (b broadcastToNewParty1) RoundNumber() round.Number {
	return 2
}

// Finalize function is used to execute the second round of the key resharing protocol. Old parties return directly to the next round, and New parties execute this round.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	log.Info(r.Info.SelfID, " initiates round2 Finalize")
	//this party check whether it has already processed (verified + stored) messages from the previous round.
	if !r.CheckOK() {
		err := errors.New("not all OK")
		return r, err
	}
	//reset all the OK flags to false
	r.resetOK()
	//reset the "oldOK" flag to true.
	r.allOldOK()
	//now all the oldok are true, and all the newok are false.
	//Because the message of this round is sent by the new party, so all the newok are false, only when the message of this round is successfully stored, the corresponding newok will be set to true.
	if !r.Info.IsNewCommittee { //old party
		nextRound := &round3{
			round2: r}
		return nextRound, nil
	} else { //new , new and old
		//Generate Paillier public key and private key
		PaillierSecret := paillier.NewSecretKey(nil)
		SelfPaillierPublic := PaillierSecret.PublicKey
		//Generate Pedersen public key and private key
		SelfPedersenPublic, PedersenSecret := PaillierSecret.GeneratePedersen()
		//Generate ElGamal public key and private key
		ElGamalSecret, ElGamalPublic := sample.ScalarPointPair(rand.Reader, r.Group())

		// Generate Schnorr randomness
		SchnorrRand := zksch.NewRandomness(rand.Reader, r.Group(), nil)
		// Sample RIDᵢ
		SelfRID, err := types.NewRID(rand.Reader)
		if err != nil {
			log.Errorln("failed to sample Rho")
			return r, err
		}
		// Sample chainKey
		chainKey, err := types.NewRID(rand.Reader)
		if err != nil {
			log.Errorln("failed to sample c")
			return r, err
		}
		// Make a hash commitment of data
		SelfCommitment, Decommitment, err := r.HashForID(r.SelfID()).Commit(
			SelfRID, chainKey, SchnorrRand.Commitment(), ElGamalPublic,
			SelfPedersenPublic.N(), SelfPedersenPublic.S(), SelfPedersenPublic.T())
		if err != nil {
			log.Errorln("failed to commit")
			return r, err
		}
		//broadcast the commitment to other new parties
		for _, j := range r.Info.NewPartyIDs {
			if j == r.SelfID() {
				continue
			}
			err := r.SendMessage(out, &broadcastToNewParty2{
				Commitment: SelfCommitment,
			}, j)
			if err != nil {
				return r, err
			}
		}
		nextRound := &round3{
			round2:         r,
			Commitments:    map[party.ID]hash.Commitment{r.SelfID(): SelfCommitment},
			RIDs:           map[party.ID]types.RID{r.SelfID(): SelfRID},
			ChainKeys:      map[party.ID]types.RID{r.SelfID(): chainKey},
			ElGamalPublic:  map[party.ID]curve.Point{r.SelfID(): ElGamalPublic},
			PaillierPublic: map[party.ID]*paillier.PublicKey{r.SelfID(): SelfPaillierPublic},
			NModulus:       map[party.ID]*BigInt.Nat{r.SelfID(): SelfPedersenPublic.N()},
			S:              map[party.ID]*BigInt.Nat{r.SelfID(): SelfPedersenPublic.S()},
			T:              map[party.ID]*BigInt.Nat{r.SelfID(): SelfPedersenPublic.T()},
			ElGamalSecret:  ElGamalSecret,
			PaillierSecret: PaillierSecret,
			PedersenSecret: PedersenSecret,
			SchnorrRand:    SchnorrRand,
			Decommitment:   Decommitment,
		}
		return nextRound, nil
	}
}

// MessageContent implements round.Round.
func (r *round2) MessageContent() round.Content {
	return &broadcastToNewParty1{
		ECDSAOldParty: r.Group().NewPoint(),
	}
}

// VerifyMessage implements round.Round.
// new party verifies the message sent by old party in round1
func (r *round2) VerifyMessage(msg round.Message) error {
	log.Info(r.Info.SelfID, " initiates round2 VerifyMessage")
	if r.Info.IsNewCommittee { //new party verifies the message sent by old party in round1
		body, ok := msg.Content.(*broadcastToNewParty1)
		if !ok || body == nil {
			return round.ErrInvalidContent
		}
		if err := body.CommitmentOldParty.Validate(); err != nil {
			log.Errorln("fail to validate commit")
			return err
		}
		return nil
	} else { //old party return nil,because old party does not receive any message in round1
		return nil
	}
}

// StoreMessage implements round.Round.
// if the VerifyMessage is passed, then store the message in round2
func (r *round2) StoreMessage(msg round.Message) error {
	log.Info(r.Info.SelfID, " initiates round2 StoreMessage")
	if r.Info.IsNewCommittee { //new party stores the message sent by old party in round1
		body, ok := msg.Content.(*broadcastToNewParty1)
		if !ok || body == nil {
			return round.ErrInvalidContent
		}
		r.CommitmentsOldParty[msg.From] = body.CommitmentOldParty
		r.ECDSAOldParty = body.ECDSAOldParty
		//If the new party has store messages from the old party(msg.From), then set the OldOK of the old party to true.
		r.Info.OldOK[msg.From] = true
		return nil
	} else {
		return nil
	}
}

// check if all old parties have store the message from the previous round
func (r *round2) CheckOK() bool {
	//Check if new party has stored messages sent by old parties in round 1.
	if r.Info.IsNewCommittee {
		for _, j := range r.Info.OldPartyIDs {
			if !r.Info.OldOK[j] {
				return false
			}
		}
		return true
	} else { //old party return true,because old party does not receive any message in round1
		return true
	}
}

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
