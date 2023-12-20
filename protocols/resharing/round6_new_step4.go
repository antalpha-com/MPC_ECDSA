// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/types"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/polynomial"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pedersen"
	zkmod "MPC_ECDSA/pkg/zk/mod"
	zkprm "MPC_ECDSA/pkg/zk/prm"
	"MPC_ECDSA/protocols/config"
	"errors"
	log "github.com/sirupsen/logrus"
)

type round6 struct {
	//By embedding round1, the round2 struct inherits all the fields and methods defined in round1
	*round5
	// RID = ⊕ⱼ RIDⱼ
	// Random ID generated by taking the XOR of all ridᵢ
	RID types.RID
	// ChainKey is a sequence of random bytes agreed upon together
	ChainKey      types.RID
	ECDSANewParty curve.Scalar
}
type broadcastToNewParty4 struct {
	Mod *zkmod.Proofbuf
	Prm *zkprm.Proofbuf
}

// VerifyMessage- verify Mod, Prm proof for N
func (r *round6) VerifyMessage(msg round.Message) error {
	log.Info(r.Info.SelfID, " initiates round 6 VerifyMessage ")
	if r.Info.IsNewCommittee { //new party verify Mod, Prm proof for N
		from := msg.From
		body, ok := msg.Content.(*broadcastToNewParty4)
		if !ok || body == nil {
			return round.ErrInvalidContent
		}
		// verify zkmod
		if !body.Mod.VerifyMal(zkmod.Public{N: r.NModulus[from]}, r.HashForID(from), r.Pool) {
			log.Errorln("round6 failed to validate mod proof")
			//return errors.New("failed to validate mod proof")
		}
		// verify zkprm
		if !body.Prm.VerifyMal(zkprm.Public{N: r.NModulus[from], S: r.S[from], T: r.T[from]}, r.HashForID(from), r.Pool) {
			log.Errorln("round6 failed to validate prm proof")
			//return errors.New("failed to validate prm proof")
		}
		//reset the "ok" flag to true if the message from round5 new party is verified.
		r.Info.NewOK[from] = true
		return nil
	} else {
		return nil
	}
}

func (r *round6) StoreMessage(msg round.Message) error {
	log.Info(r.Info.SelfID, " initiates round 6 StoreMessage ")
	return nil
}

func (b broadcastToNewParty4) RoundNumber() round.Number {
	return 6
}

// Finalize function is used to execute the 6th round of the key resharing protocol. Old parties return directly to the next round, and New parties execute this round.
func (r *round6) Finalize(out chan<- *round.Message) (round.Session, error) {
	log.Info(r.Info.SelfID, " initiates round6 Finalize")
	// Check if all parties have store the message from the previous round
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

	if !r.Info.IsNewCommittee { //old party return directly to the next round
		nextRound := &round7{
			round6: r,
		}
		return nextRound, nil
	} else {
		// ShamirPublicPolynomials is a slice to store the Shamir public polynomials
		ShamirPublicPolynomials := make([]*polynomial.Exponent, 0, len(r.VSSPolynomialNewParty))
		// Append the VSS polynomial to the ShamirPublicPolynomials slice.
		for _, VSSPolynomial := range r.VSSPolynomialNewParty {
			ShamirPublicPolynomials = append(ShamirPublicPolynomials, VSSPolynomial)
		}
		// ShamirPublicPolynomial = F(X) = ∑Fⱼ(X)
		ShamirPublicPolynomial, err := polynomial.Sum(ShamirPublicPolynomials)
		if err != nil {
			return r, err
		}
		// compute the new public key share Xⱼ = F(j) (+X'ⱼ if doing a refresh)
		PublicData := make(map[party.ID]*config.Public, len(r.Info.NewPartyIDs))
		Fj := ShamirPublicPolynomial.Evaluate(r.SelfID().Scalar(r.Group()))
		fjG := r.ECDSANewParty.ActOnBase()
		if !Fj.Equal(fjG) {
			log.Errorln("Fj is not equal to fjG ")
		}
		for _, j := range r.Info.NewPartyIDs {
			// Evaluate the Shamir public polynomial at party j's scalar value (F(j)*G).
			PublicECDSAShare := ShamirPublicPolynomial.Evaluate(j.Scalar(r.Group()))
			// PublicData is a map of party IDs to their respective public data.
			PublicData[j] = &config.Public{
				ECDSA:    PublicECDSAShare,
				ElGamal:  r.ElGamalPublic[j],
				Paillier: r.PaillierPublic[j],
				Pedersen: pedersen.New(r.PaillierPublic[j].Modulus(), r.S[j], r.T[j]),
			}
		}
		UpdatedConfig := &config.Config{
			Group:     r.Group(),
			ID:        r.SelfID(),
			Threshold: r.Threshold(),
			ECDSA:     r.ECDSANewParty, //F(x_i)
			ElGamal:   r.ElGamalSecret,
			Paillier:  r.PaillierSecret,
			RID:       r.RID.Copy(),
			ChainKey:  r.ChainKey.Copy(),
			Public:    PublicData,
		}
		//write new ssid to hash, to bind the Schnorr proof to this new config
		//Write SSID, selfID to temporary hash
		h := r.Hash()
		_ = h.WriteAny(UpdatedConfig, r.SelfID())
		// Generate Schnorr proof
		proof := r.SchnorrRand.Prove(h, PublicData[r.SelfID()].ECDSA, r.ECDSANewParty, nil)
		// Broadcast the Schnorr proof to other new parties
		for _, j := range r.Info.NewPartyIDs {
			if j == r.SelfID() {
				continue
			}
			err = r.SendMessage(out, &broadcastToNewParty5{SchnorrResponse: proof}, j)
		}
		if err != nil {
			return r, err
		}
		// Update the hash state with the updated configuration (UpdatedConfig).
		r.UpdateHashState(UpdatedConfig)
		return &round7{
			round6:        r,
			UpdatedConfig: UpdatedConfig,
		}, nil
	}
}

// check if all parties have store the message from the previous round
func (r *round6) CheckOK() bool {
	if r.Info.IsNewCommittee { //new party checks if it has stored messages sent by new parties in round 5
		for _, j := range r.Info.NewPartyIDs {
			if j == r.Info.SelfID {
				continue
			}
			if !r.Info.NewOK[j] {
				return false
			}
		}
		return true
	} else {
		return true
	}
}

// Number implements round.Round.
func (round6) Number() round.Number { return 6 }

func (r *round6) MessageContent() round.Content {
	return &broadcastToNewParty4{
		Mod: &zkmod.Proofbuf{},
		Prm: &zkprm.Proofbuf{},
	}
}
