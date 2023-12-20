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
	"MPC_ECDSA/pkg/math/polynomial"
	"MPC_ECDSA/pkg/party"
	zksch "MPC_ECDSA/pkg/zk/sch"
	"errors"
	log "github.com/sirupsen/logrus"
)

type round4 struct {
	//By embedding round1, the round2 struct inherits all the fields and methods defined in round1
	*round3
	SchnorrCommitments map[party.ID]*zksch.Commitment // Aⱼ,
}
type messageToNewParty3 struct {
	ShareOldParty          curve.Scalar
	DeCommitmentsOldParty  hash.Decommitment
	VSSPolynomialsOldParty *polynomial.Exponent
}

func (m messageToNewParty3) RoundNumber() round.Number {
	return 4
}

// VerifyMessage implements round.Round.
func (r *round4) VerifyMessage(msg round.Message) error {
	log.Info(r.Info.SelfID, " initiates round4 VerifyMessage")
	if r.Info.IsNewCommittee {
		//验证哈希
		body, ok := msg.Content.(*messageToNewParty3)
		if !ok || body == nil {
			log.Errorln("fail to get body")
			return round.ErrInvalidContent
		}
		if body.DeCommitmentsOldParty.Validate() != nil {
			log.Errorln("fail to validate commitments")
			return errors.New("invalid commitments")
		}
		from := msg.From
		if !r.HashForID(from).Decommit(r.CommitmentsOldParty[from], body.DeCommitmentsOldParty,
			body.VSSPolynomialsOldParty) {
			log.Errorln("failed to decommit")
		}
		//验证X == Fⱼ(i)，Fⱼ(i)是参与方j发送给参与方i的vss多项式F_j(用基点加密后)带入i的值, X是参与方i收到的来自参与方j的share乘以基点G
		ExpectedPublicShare := body.VSSPolynomialsOldParty.Evaluate(r.SelfID().Scalar(r.Group())) // 别人的Fⱼ(x_i)
		PublicShare := body.ShareOldParty.ActOnBase()

		if !PublicShare.Equal(ExpectedPublicShare) {
			return errors.New("failed to validate VSS share")
		}
		return nil
	} else {
		return nil
	}
}

// StoreMessage implements round.Round.
func (r *round4) StoreMessage(msg round.Message) error {
	log.Info(r.Info.SelfID, " initiates round4 StoreMessage")
	if r.Info.IsNewCommittee {
		from, body := msg.From, msg.Content.(*messageToNewParty3)
		r.ShareReceivedOldParty[from] = body.ShareOldParty
		r.VSSPolynomialsOldParty[from] = body.VSSPolynomialsOldParty
		//If the new party has store messages from the old party(From), then set the OldOK[from] to true.
		r.Info.OldOK[from] = true
		return nil
	} else {
		return nil
	}
}

// CheckOK checks if all parties have store the message from the previous round.
func (r *round4) CheckOK() bool {
	if r.Info.IsNewCommittee { //new party checks if it has stored messages sent by old parties in round 3.
		for _, j := range r.Info.OldPartyIDs {
			if !r.Info.OldOK[j] {
				return false
			}
		}
		return true
	} else {
		return true
	}
}

// Finalize function is used to execute the 4th round of the key resharing protocol. Old parties return directly to the next round, and New parties execute this round.
func (r *round4) Finalize(out chan<- *round.Message) (round.Session, error) {
	log.Info(r.Info.SelfID, " initiates round4 Finalize")
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

	if !r.Info.IsNewCommittee { //old party return directly to the next round
		nextRound := &round5{
			round4: r,
		}
		return nextRound, nil
	} else {

		// ShamirPublicPolynomials is a slice to store the Shamir public polynomials
		ShamirPublicPolynomialsOldParty := make([]*polynomial.Exponent, 0, len(r.VSSPolynomialsOldParty))
		// Append the VSS polynomial to the ShamirPublicPolynomials slice.
		for _, VSSPolynomial := range r.VSSPolynomialsOldParty {
			ShamirPublicPolynomialsOldParty = append(ShamirPublicPolynomialsOldParty, VSSPolynomial)
		}
		// ShamirPublicPolynomial = F(X) = ∑Fⱼ(X)
		ShamirPublicPolynomialOldParty, err := polynomial.Sum(ShamirPublicPolynomialsOldParty)

		group := r.Info.Group
		//F(x_i)=∑fⱼ(x_i)
		ReshareECDSAFromOldParty := r.Group().NewScalar()
		for _, j := range r.Info.OldPartyIDs {
			ReshareECDSAFromOldParty.Add(r.ShareReceivedOldParty[j]) //f(x_i)=∑fⱼ(x_i)
		}
		//check y(1)G==Y(1), wherey(1)=ReshareECDSAFromOldParty，F(1)=ShamirPublicPolynomialOldParty(1)
		Fj := ShamirPublicPolynomialOldParty.Evaluate(r.SelfID().Scalar(r.Group()))
		fjG := ReshareECDSAFromOldParty.ActOnBase()
		if !Fj.Equal(fjG) {
			println("Fj is not equal")
		}
		//calculate the lagrange  []l_i(0)
		lagrange := polynomial.Lagrange(r.Info.Group, r.Info.NewPartyIDs) // map of Lagrange coefficient id:l_i(0)
		SecretECDSA := group.NewScalar().Set(lagrange[r.SelfID()]).Mul(ReshareECDSAFromOldParty)
		//Taking one's current secret share w_i as a constant in the polynomial, generate a new local polynomial VSSSecret f_i(x).
		VSSSecretNewParty := polynomial.NewPolynomial(group, r.Info.NewThreshold, SecretECDSA)
		// Compute Fᵢ(X) = fᵢ(X)•G
		VSSPolynomialNewParty := polynomial.NewPolynomialExponent(VSSSecretNewParty)

		//calculate the share of self
		SelfShareNewParty := VSSSecretNewParty.Evaluate(r.SelfID().Scalar(r.Group())) // f'_i(i)
		//calculate the share of other new parties
		sharesFromNewParty := make(map[party.ID]curve.Scalar, len(r.Info.NewPartyIDs))
		//f'_i(j)
		for _, j := range r.Info.NewPartyIDs {
			share := VSSSecretNewParty.Evaluate(j.Scalar(r.Group()))
			sharesFromNewParty[j] = share
		}
		// Make a hash commitment of VSSPolynomialNewParty
		SelfCommitmentNewParty, SelfDecommitmentNewParty, err := r.HashForID(r.SelfID()).Commit(VSSPolynomialNewParty)
		if err != nil {
			log.Errorln("failed to commit")
			return r, err
		}
		//broadcast the message to other new parties
		SelfSchnorrCommitment := r.SchnorrRand.Commitment()
		for _, j := range r.Info.NewPartyIDs {
			if j == r.SelfID() {
				continue
			}
			err := r.SendMessage(out, &broadcast3{
				RID:                      r.RIDs[r.SelfID()],
				C:                        r.ChainKeys[r.SelfID()],
				VSSPolynomialNewParty:    VSSPolynomialNewParty, //这里的vsspolynomial是什么？
				SchnorrCommitments:       SelfSchnorrCommitment,
				ElGamalPublic:            r.ElGamalPublic[r.SelfID()],
				N:                        r.NModulus[r.SelfID()],
				S:                        r.S[r.SelfID()],
				T:                        r.T[r.SelfID()],
				Decommitment:             r.Decommitment,
				SelfCommitmentNewParty:   SelfCommitmentNewParty,
				SelfDecommitmentNewParty: SelfDecommitmentNewParty,
				ShareNewParty:            sharesFromNewParty[j],
			}, j)
			if err != nil {
				log.Errorln("fail to send message")
				return r, err
			}
		}
		return &round5{
			round4:                r,
			SchnorrCommitments:    map[party.ID]*zksch.Commitment{r.SelfID(): SelfSchnorrCommitment},
			VSSPolynomialNewParty: map[party.ID]*polynomial.Exponent{r.SelfID(): VSSPolynomialNewParty},
			VSSSecretNewParty:     VSSSecretNewParty,
			ShareReceivedNewParty: map[party.ID]curve.Scalar{r.SelfID(): SelfShareNewParty},
		}, nil
	}
}

// PreviousRound implements round.Round.
func (r *round4) PreviousRound() round.Round { return r.round1 }

// MessageContent implements round.Round.
func (r *round4) MessageContent() round.Content {
	return &messageToNewParty3{
		ShareOldParty:          r.Group().NewScalar(),
		VSSPolynomialsOldParty: polynomial.EmptyExponent(r.Group()),
	}
}

// Number implements round.Round.
func (round4) Number() round.Number { return 4 }
