package presign

import (
	"errors"

	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	zkelog "MPC_ECDSA/pkg/zk/elog"

	"MPC_ECDSA/pkg/BigInt"
)

var _ round.Round = (*presign6)(nil)

type presign6 struct {
	*presign5

	// BigDeltaShares[j] = Δⱼ = [kⱼ]•Γⱼ
	BigDeltaShares map[party.ID]curve.Point

	// Gamma = ∑ᵢ Γᵢ
	Gamma curve.Point
}

type broadcast6 struct {
	round.NormalBroadcastContent
	// BigDeltaShare = Δⱼ = [kⱼ]•Γⱼ
	BigDeltaShare curve.Point
	Proof         *zkelog.Proofbuf
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - save Δⱼ and verify proof.
func (r *presign6) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast6)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.BigDeltaShare.IsIdentity() {
		return round.ErrNilFields
	}

	if !body.Proof.VerifyMal(r.Group(), r.HashForID(from), zkelog.Public{
		E:             r.ElGamalK[from],
		ElGamalPublic: r.ElGamal[from],
		Base:          r.Gamma,
		Y:             body.BigDeltaShare,
	}) {
		return errors.New("failed to validate elog proof for BigDeltaShare")
	}

	r.BigDeltaShares[from] = body.BigDeltaShare
	return nil
}

// VerifyMessage implements round.Round.
func (presign6) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *presign6) StoreMessage(msg round.Message) error { return nil }

// Finalize implements round.Round
//
// - compute δ = ∑ⱼ δⱼ,
// - compute R = [δ⁻¹] Γ,
// - compute Sᵢ = χᵢ⋅R,
// - compute {R̄ⱼ = δ⁻¹⋅Δⱼ}ⱼ.
func (r *presign6) Finalize(out chan<- *round.Message) (round.Session, error) {
	// δ = ∑ⱼ δⱼ
	Delta := r.Group().NewScalar()
	for _, DeltaJ := range r.DeltaShares {
		Delta.Add(DeltaJ)
	}

	// δ⁻¹
	DeltaInv := r.Group().NewScalar().Set(Delta).Invert()

	// R = [δ⁻¹] Γ
	R := DeltaInv.Act(r.Gamma)

	// δ⋅G
	BigDeltaExpected := Delta.ActOnBase()

	// ∑ⱼΔⱼ
	BigDeltaActual := r.Group().NewPoint()
	for _, BigDeltaJ := range r.BigDeltaShares {
		BigDeltaActual = BigDeltaActual.Add(BigDeltaJ)
	}

	// δ⋅G ?= ∑ⱼΔⱼ
	if !BigDeltaActual.Equal(BigDeltaExpected) {
		DeltaProofs := make(map[party.ID]*abortNth, r.N()-1)
		for _, j := range r.OtherPartyIDs() {
			deltaCiphertext := r.DeltaCiphertext[j][r.SelfID()] // Dᵢⱼ
			DeltaProofs[j] = proveNth(r.HashForID(r.SelfID()), r.SecretPaillier, deltaCiphertext)
		}
		msg := &broadcastAbort1{
			GammaShare:  r.GammaShare,
			KProof:      proveNth(r.HashForID(r.SelfID()), r.SecretPaillier, r.K[r.SelfID()]),
			DeltaProofs: DeltaProofs,
		}
		if err := r.BroadcastMessage(out, msg); err != nil {
			return r, err
		}
		return &abort1{
			presign6:    r,
			GammaShares: map[party.ID]*BigInt.Nat{r.SelfID(): r.GammaShare},
			KShares:     map[party.ID]*BigInt.Nat{r.SelfID(): curve.MakeInt(r.KShare)},
			DeltaAlphas: map[party.ID]map[party.ID]*BigInt.Nat{r.SelfID(): r.DeltaShareAlpha},
		}, nil
	}
	//If BigDeltaActual is equal to BigDeltaExpected
	// Sᵢ = χᵢ⋅R,
	S := r.ChiShare.Act(R)

	// {R̄ⱼ = δ⁻¹⋅Δⱼ}ⱼ
	RBar := make(map[party.ID]curve.Point, r.N())
	for j, BigDeltaJ := range r.BigDeltaShares {
		RBar[j] = DeltaInv.Act(BigDeltaJ)
	}
	//A proof is constructed using zkelog.NewProofMal with the public parameters and the private parameters
	proof := zkelog.NewProofMal(r.Group(), r.HashForID(r.SelfID()), zkelog.Public{
		E:             r.ElGamalChi[r.SelfID()],
		ElGamalPublic: r.ElGamal[r.SelfID()],
		Base:          R,
		Y:             S,
	}, zkelog.Private{
		Y:      r.ChiShare,
		Lambda: r.ElGamalChiNonce,
	})
	// broadcast to all other parties
	err := r.BroadcastMessage(out, &broadcast7{
		S:              S,
		Proof:          proof,
		DecommitmentID: r.DecommitmentID, //presign1生成的
		PresignatureID: r.PresignatureID[r.SelfID()],
	})
	if err != nil {
		return r, err.(error)
	}

	return &presign7{
		presign6: r,
		Delta:    Delta,
		S:        map[party.ID]curve.Point{r.SelfID(): S},
		R:        R,
		RBar:     RBar,
	}, nil
}

// MessageContent implements round.Round.
func (presign6) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast6) RoundNumber() round.Number { return 6 }

// BroadcastContent implements round.BroadcastRound.
func (r *presign6) BroadcastContent() round.BroadcastContent {
	return &broadcast6{
		BigDeltaShare: r.Group().NewPoint(),
		//Proof:         zkelog.Empty(r.Group()),
		Proof: &zkelog.Proofbuf{},
	}
}

// Number implements round.Round.
func (presign6) Number() round.Number { return 6 }
