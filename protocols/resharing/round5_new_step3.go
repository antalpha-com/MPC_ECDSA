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

	//"MPC_ECDSA/pkg/math/polynomial"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pedersen"
	zkmod "MPC_ECDSA/pkg/zk/mod"
	zkprm "MPC_ECDSA/pkg/zk/prm"
	zksch "MPC_ECDSA/pkg/zk/sch"
	"errors"
	log "github.com/sirupsen/logrus"
)

type round5 struct {
	//By embedding round1, the round2 struct inherits all the fields and methods defined in round1
	*round4
	SchnorrCommitments    map[party.ID]*zksch.Commitment // Aⱼ,
	ECDSA                 curve.Scalar
	VSSPolynomialNewParty map[party.ID]*polynomial.Exponent
	VSSSecretNewParty     *polynomial.Polynomial
	ShareReceivedNewParty map[party.ID]curve.Scalar
}

type broadcast3 struct {
	//round.NormalBroadcastContent
	// RID = RIDᵢ
	RID types.RID
	C   types.RID

	// SchnorrCommitments = Aᵢ Schnorr commitment for the final confirmation
	SchnorrCommitments *zksch.Commitment
	ElGamalPublic      curve.Point
	// N Paillier and Pedersen N = p•q, p ≡ q ≡ 3 mod 4
	N *BigInt.Nat
	// S = r² mod N
	S *BigInt.Nat
	// T = Sˡ mod N
	T *BigInt.Nat
	// Decommitment = uᵢ decommitment bytes
	Decommitment             hash.Decommitment
	SelfCommitmentNewParty   hash.Commitment
	SelfDecommitmentNewParty hash.Decommitment
	// VSSPolynomial = Fᵢ(X) VSSPolynomial
	VSSPolynomialNewParty *polynomial.Exponent
	ShareNewParty         curve.Scalar
}

// RoundNumber implements round.Round.
func (b broadcast3) RoundNumber() round.Number {
	return 5
}

// StoreMessage implements round.Round.
func (r *round5) StoreMessage(msg round.Message) error {
	log.Info(r.Info.SelfID, " initiates round5 StoreMessage")

	if r.Info.IsNewCommittee { //new party stores messages sent by new parties in round 4.
		from := msg.From
		body, ok := msg.Content.(*broadcast3)
		if !ok || body == nil {
			return round.ErrInvalidContent
		}
		r.RIDs[from] = body.RID
		r.ChainKeys[from] = body.C
		r.NModulus[from] = body.N
		r.S[from] = body.S
		r.T[from] = body.T
		r.PaillierPublic[from] = paillier.NewPublicKeyFromN(body.N)
		r.SchnorrCommitments[from] = body.SchnorrCommitments
		r.ElGamalPublic[from] = body.ElGamalPublic
		r.VSSPolynomialNewParty[from] = body.VSSPolynomialNewParty
		r.ShareReceivedNewParty[from] = body.ShareNewParty
		//If the new party has store messages from the new party(msg.From), then set the NewOK of the new party to true.
		r.Info.NewOK[from] = true
		return nil
	} else {
		return nil
	}
}

// VerifyMessage implements round.Round.
func (r *round5) VerifyMessage(msg round.Message) error {
	log.Info(r.Info.SelfID, " initiates round5 VerifyMessage")

	if r.Info.IsNewCommittee {
		from := msg.From
		body, ok := msg.Content.(*broadcast3)
		if !ok || body == nil {
			return round.ErrInvalidContent
		}
		// check nil
		if body.N == nil || body.S == nil || body.T == nil || body.VSSPolynomialNewParty == nil {
			return round.ErrNilFields
		}
		// check RID length
		if err := body.RID.Validate(); err != nil {
			log.Errorln(err)
			return err
		}
		if err := body.C.Validate(); err != nil {
			log.Errorln(err)
			return err
		}
		// check decommitment
		if err := body.Decommitment.Validate(); err != nil {
			log.Errorln(err)
			return err
		}
		// Save all X, VSSCommitments
		VSSPolynomial := body.VSSPolynomialNewParty

		// check deg(Fⱼ) = t
		if VSSPolynomial.Degree() != r.Info.NewThreshold {
			log.Errorln("vss polynomial has incorrect degree")
			return errors.New("vss polynomial has incorrect degree")
		}

		// Set Paillier
		if err := paillier.ValidateN(body.N); err != nil {
			log.Errorln(err)
			return err
		}

		// Verify Pedersen
		if err := pedersen.ValidateParameters(body.N, body.S, body.T); err != nil {
			log.Errorln(err)
			return err
		}
		// Verify decommit
		if !r.HashForID(from).Decommit(r.Commitments[from], body.Decommitment,
			body.RID, body.C, body.SchnorrCommitments, body.ElGamalPublic, body.N, body.S, body.T) {
			log.Errorln("failed to decommit")
			return errors.New("failed to decommit")
		}
		if !r.HashForID(from).Decommit(body.SelfCommitmentNewParty, body.SelfDecommitmentNewParty, body.VSSPolynomialNewParty) {
			log.Errorln("failed to decommit")
			return errors.New("failed to decommit")
		}
		//check if X == Fⱼ(i), Fⱼ(i) is the vss polynomial F_j (encrypted with the base point) sent by party j to party i with the value of i,
		//and X is the share received by party i from party j multiplied by the base point G
		ExpectedPublicShare := body.VSSPolynomialNewParty.Evaluate(r.SelfID().Scalar(r.Group())) // 别人的Fⱼ(x_i)
		PublicShare := body.ShareNewParty.ActOnBase()

		if !PublicShare.Equal(ExpectedPublicShare) {
			return errors.New("failed to validate VSS share")
		}

		return nil
	} else {
		return nil
	}
}

// Finalize function is used to execute the 5th round of the key resharing protocol. Old parties return directly to the next round, and New parties execute this round.
func (r *round5) Finalize(out chan<- *round.Message) (round.Session, error) {
	log.Info(r.Info.SelfID, " initiates round5 Finalize")
	//check whether it has already processed (verified + stored) messages from the previous round.
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

	if !r.Info.IsNewCommittee { //old
		nextRound := &round6{
			round5: r,
		}
		return nextRound, nil
	} else { //new, new and old
		// Compute f'(x_i)=∑f'ⱼ(x_i)
		ReshareECDSAFromNewParty := r.Group().NewScalar()
		for _, j := range r.Info.NewPartyIDs {
			ReshareECDSAFromNewParty.Add(r.ShareReceivedNewParty[j])
		}
		chainKey := types.EmptyRID()
		for _, j := range r.Info.NewPartyIDs {
			chainKey.XOR(r.ChainKeys[j])
		}
		// Compute RID = ⊕ⱼ RIDⱼ
		rid := types.EmptyRID()
		for _, j := range r.Info.NewPartyIDs {
			rid.XOR(r.RIDs[j])
		}

		// temporary hash which does not modify the state
		h := r.Hash()
		_ = h.WriteAny(rid, r.SelfID())

		// Prove N is a blum prime with zkmod n = pq
		mod := zkmod.NewProofMal(h.Clone(), zkmod.Private{
			P:   r.PaillierSecret.P(),
			Q:   r.PaillierSecret.Q(),
			Phi: r.PaillierSecret.Phi(),
		}, zkmod.Public{N: r.NModulus[r.SelfID()]}, r.Pool)

		// Prove s, t are correct as aux parameters with zkprm s = t^lambda (mod N).
		prm := zkprm.NewProofMal(zkprm.Private{
			Lambda: r.PedersenSecret,
			Phi:    r.PaillierSecret.Phi(),
			P:      r.PaillierSecret.P(),
			Q:      r.PaillierSecret.Q(),
		}, h.Clone(), zkprm.Public{N: r.NModulus[r.SelfID()], S: r.S[r.SelfID()], T: r.T[r.SelfID()]}, r.Pool)
		// Broadcast the proof to the new parties
		for _, j := range r.Info.NewPartyIDs {
			if j == r.Info.SelfID {
				continue
			}
			if err := r.SendMessage(out, &broadcastToNewParty4{
				Mod: mod,
				Prm: prm,
			}, j); err != nil {
				return r, err
			}
		}
		// Write rid to the hash state
		r.UpdateHashState(rid)
		return &round6{
			round5:        r,
			ECDSANewParty: ReshareECDSAFromNewParty,
			RID:           rid,
			ChainKey:      chainKey,
		}, nil
	}
}

// check if all parties have store the message from the previous round
func (r *round5) CheckOK() bool {
	if r.Info.IsNewCommittee { //new party checks if it has stored messages sent by new parties in round 4.
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
func (round5) Number() round.Number { return 5 }

func (r *round5) MessageContent() round.Content {
	return &broadcast3{
		ElGamalPublic:         r.Group().NewPoint(),
		VSSPolynomialNewParty: polynomial.EmptyExponent(r.Group()),
		SchnorrCommitments:    zksch.EmptyCommitment(r.Group()),
		ShareNewParty:         r.Group().NewScalar(),
	}
}
