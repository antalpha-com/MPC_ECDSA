// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/protocols/config"
	"errors"

	"MPC_ECDSA/pkg/math/polynomial"
	log "github.com/sirupsen/logrus"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	//The auxiliary information before the first round, embedded in round1
	*round.Helper
}

// VerifyMessage implements round.Round.
func (r *round1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round1) StoreMessage(round.Message) error { return nil }

// resetOK resets the "OK" flags for all parties(new parties and old parties) IDs to false.
func (r *round1) resetOK() {

	for _, j := range r.Info.OldPartyIDs {
		r.Info.OldOK[j] = false
	}
	for _, j := range r.Info.NewPartyIDs {
		r.Info.NewOK[j] = false
	}
}

// allOldOK resets the "OldOK" flags to true
func (r *round1) allOldOK() {
	for _, j := range r.Info.OldPartyIDs {
		r.Info.OldOK[j] = true
	}
}

// allNewOK resets the "NewOK" flags to true
func (r *round1) allNewOK() {
	for _, j := range r.Info.NewPartyIDs {
		r.Info.NewOK[j] = true
	}
}

// Finalize function is used to execute the first round of the key resharing protocol. New parties return directly to the next round, and old parties execute this round.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	log.Info(r.Info.SelfID, " initiates round 1 Finalize ")
	//check if all parties have stored their messages from the previous round
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

	//if this party isn't an old party, then it return.
	if !r.Helper.Info.IsOldCommittee {
		nextRound := &round2{
			round1:                 r,
			CommitmentsOldParty:    map[party.ID]hash.Commitment{},
			VSSPolynomialsOldParty: map[party.ID]*polynomial.Exponent{},
			ShareReceivedOldParty:  map[party.ID]curve.Scalar{},
		}
		return nextRound, nil
	} else { //if this party is an old party
		//get the keygen result
		KeyGenResult, ok := r.Info.KeyGenConfig.(*config.Config)
		if !ok {
			log.Println("fail to get keygenconfig")
		}
		group := r.Info.Group
		//calculate the Lagrange coefficient of all old parties
		lagrange := polynomial.Lagrange(group, r.Info.OldPartyIDs) // map of Lagrange coefficient id:l_i(0)
		// Scale own secret
		//The Lagrange coefficient of this party is multiplied by the private key l_i(0)*y(i),where y(i) is the old party's secret share
		SecretECDSA := group.NewScalar().Set(lagrange[KeyGenResult.ID]).Mul(KeyGenResult.ECDSA)
		// let the SecretECDSA be the constant of the polynomial,
		//and generate a new local polynomial VSSSecret f_i(x)=SecretECDSA+a1*x+a2*x^2+...+at*x^t, t is the newthreshold.
		VSSSecret := polynomial.NewPolynomial(group, r.Info.NewThreshold, SecretECDSA)

		// Compute Fᵢ(X) = fᵢ(X)•G
		VSSPolynomialsOldParty := polynomial.NewPolynomialExponent(VSSSecret)

		//calculate selfshare f_i(i) and store in round
		SelfShare := VSSSecret.Evaluate(r.SelfID().Scalar(r.Group()))

		shares := make(map[party.ID]curve.Scalar, len(r.Info.NewPartyIDs))
		ECDSA := make(map[party.ID]curve.Point, len(r.Info.OldPartyIDs))
		PublicKey := group.NewPoint()
		//calcute the publickey=∑F(j)
		for _, j := range r.Info.OldPartyIDs {
			public := KeyGenResult.Public[j] // Public information of j (public key & parameters)
			// scale public key share
			ECDSA[j] = lagrange[j].Act(public.ECDSA) //Scalar multiplied by the point of the public key, returning a new point

			PublicKey = PublicKey.Add(ECDSA[j])
		}
		// compute share fᵢ(j) for new party j
		for _, j := range r.Info.NewPartyIDs {
			share := VSSSecret.Evaluate(j.Scalar(r.Group()))
			shares[j] = share
		}
		//do the commitment for the VSSPolynomialsOldParty
		SelfCommitment, SelfDecommitment, err := r.HashForID(r.SelfID()).Commit(VSSPolynomialsOldParty)
		if err != nil {
			log.Errorln("failed to commit")
			return r, err
		}
		//send the publickey and commitment to the new parties
		for _, j := range r.Info.NewPartyIDs {
			if j == r.SelfID() {
				continue
			}
			err := r.SendMessage(out, &broadcastToNewParty1{
				ECDSAOldParty:      PublicKey,
				CommitmentOldParty: SelfCommitment,
			}, j)
			if err != nil {
				return r, err
			}
		}
		nextRound := &round2{
			round1:                   r,
			SelfCommitmentOldParty:   SelfCommitment,
			SelfDecommitmentOldParty: SelfDecommitment,
			SharesOldParty:           shares,
			VSSSecretOldParty:        VSSSecret,
			VSSPolynomialsOldParty:   map[party.ID]*polynomial.Exponent{r.SelfID(): VSSPolynomialsOldParty},
			ECDSAOldParty:            PublicKey,
			CommitmentsOldParty:      map[party.ID]hash.Commitment{r.SelfID(): SelfCommitment},
			ShareReceivedOldParty:    map[party.ID]curve.Scalar{r.SelfID(): SelfShare},
		}
		return nextRound, nil
	}
}

// PreviousRound implements round.Round.
func (round1) PreviousRound() round.Round { return nil }

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }

func (r *round1) CheckOK() bool {
	return true
}
