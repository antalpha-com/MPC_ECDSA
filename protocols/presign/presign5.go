package presign

import (
	"errors"

	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	zkelog "MPC_ECDSA/pkg/zk/elog"
	zklogstar "MPC_ECDSA/pkg/zk/logstar"
)

var _ round.Round = (*presign5)(nil)

type presign5 struct {
	*presign4

	// BigGammaShare[j] = Γⱼ = [γⱼ]•G
	BigGammaShare map[party.ID]curve.Point
}

type message5 struct {
	ProofLog *zklogstar.Proofbuf
}

type broadcast5 struct {
	round.NormalBroadcastContent
	// BigGammaShare = Γᵢ
	BigGammaShare curve.Point
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - save Γⱼ
func (r *presign5) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast5)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.BigGammaShare.IsIdentity() {
		return round.ErrNilFields
	}
	r.BigGammaShare[msg.From] = body.BigGammaShare
	return nil
}

// VerifyMessage implements round.Round.
func (r *presign5) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message5)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if !body.ProofLog.VerifyMal(r.Group(), r.HashForID(msg.From), zklogstar.Public{
		C:      r.G[from],
		X:      r.BigGammaShare[from],
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}) {
		return errors.New("failed to validate log* proof for BigGammaShare")
	}

	return nil
}

// StoreMessage implements round.Round.
func (presign5) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - compute Γ = ∑ⱼ Γⱼ
// - compute Δᵢ = kᵢ⋅Γ.
// Finalize method calculates the final values Gamma and BigDeltaShare based on the collected BigGammaShare values and broadcasts them along with the corresponding proof to the other parties.
func (r *presign5) Finalize(out chan<- *round.Message) (round.Session, error) {
	//Gamma is computed as the sum of all GammaJ values in r.BigGammaShare, where GammaJ is a group point.
	// Γ = ∑ⱼ Γⱼ
	Gamma := r.Group().NewPoint()
	for _, GammaJ := range r.BigGammaShare {
		Gamma = Gamma.Add(GammaJ)
	}

	// Δᵢ = kᵢ⋅Γ
	BigDeltaShare := r.KShare.Act(Gamma)

	// 构造proof
	//A proof proofLog is constructed using zkelog.NewProofMal with the public parameters and the private parameters .
	proofLog := zkelog.NewProofMal(r.Group(), r.HashForID(r.SelfID()),
		zkelog.Public{
			E:             r.ElGamalK[r.SelfID()],
			ElGamalPublic: r.ElGamal[r.SelfID()],
			Base:          Gamma,
			Y:             BigDeltaShare,
		}, zkelog.Private{
			Y:      r.KShare,
			Lambda: r.ElGamalKNonce,
		})
	//broadcast BigDeltaShare and proofLog to all other parties
	err := r.BroadcastMessage(out, &broadcast6{
		BigDeltaShare: BigDeltaShare,
		Proof:         proofLog,
	})
	if err != nil {
		return r, err
	}

	return &presign6{
		presign5:       r,
		Gamma:          Gamma,
		BigDeltaShares: map[party.ID]curve.Point{r.SelfID(): BigDeltaShare}, // BigDeltaShares containing the BigDeltaShare values of all parties.
	}, nil
}

// RoundNumber implements round.Content.
func (message5) RoundNumber() round.Number { return 5 }

// MessageContent implements round.Round.
func (r *presign5) MessageContent() round.Content {
	return &message5{
		//ProofLog: zklogstar.Empty(r.Group()),
		ProofLog: &zklogstar.Proofbuf{},
	}
}

// RoundNumber implements round.Content.
func (broadcast5) RoundNumber() round.Number { return 5 }

// BroadcastContent implements round.BroadcastRound.
func (r *presign5) BroadcastContent() round.BroadcastContent {
	return &broadcast5{
		BigGammaShare: r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (presign5) Number() round.Number { return 5 }
