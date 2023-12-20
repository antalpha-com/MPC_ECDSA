package presign

import (
	"errors"

	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/types"
	"MPC_ECDSA/pkg/ecdsa"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	zkelog "MPC_ECDSA/pkg/zk/elog"
	zklog "MPC_ECDSA/pkg/zk/log"
)

var _ round.Round = (*presign7)(nil)

type presign7 struct {
	*presign6
	// Delta = δ = ∑ⱼ δⱼ
	Delta curve.Scalar

	// S[j] = Sⱼ
	S map[party.ID]curve.Point

	// R = [δ⁻¹] Γ
	R curve.Point

	// RBar = {R̄ⱼ = δ⁻¹⋅Δⱼ}ⱼ
	RBar map[party.ID]curve.Point
}

type broadcast7 struct {
	round.NormalBroadcastContent
	// S = Sᵢ
	S              curve.Point
	Proof          *zkelog.Proofbuf
	DecommitmentID hash.Decommitment
	PresignatureID types.RID
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - save Sⱼ and verify proof + decommitment to presignature ID.
func (r *presign7) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast7)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.S.IsIdentity() {
		return round.ErrNilFields
	}

	if err := body.DecommitmentID.Validate(); err != nil {
		return err
	}
	if err := body.PresignatureID.Validate(); err != nil {
		return err
	}
	if !r.HashForID(from).Decommit(r.CommitmentID[from], body.DecommitmentID, body.PresignatureID) {
		return errors.New("failed to decommit presignature ID")
	}

	if !body.Proof.VerifyMal(r.Group(), r.HashForID(from), zkelog.Public{
		E:             r.ElGamalChi[from],
		ElGamalPublic: r.ElGamal[from],
		Base:          r.R,
		Y:             body.S,
	}) {
		return errors.New("failed to validate elog proof for S")
	}
	r.S[from] = body.S
	r.PresignatureID[from] = body.PresignatureID

	return nil
}

// VerifyMessage implements round.Round.
func (presign7) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (presign7) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - verify ∑ⱼ Sⱼ = X.
func (r *presign7) Finalize(out chan<- *round.Message) (round.Session, error) {
	// compute ∑ⱼ Sⱼ
	PublicKeyComputed := r.Group().NewPoint()
	for _, Sj := range r.S {
		PublicKeyComputed = PublicKeyComputed.Add(Sj)
	}
	//presignatureID is computed by performing XOR operation on all id values in r.PresignatureID.
	presignatureID := types.EmptyRID()
	for _, id := range r.PresignatureID {
		presignatureID.XOR(id)
	}

	// ∑ⱼ Sⱼ ?= X
	//If the computed PublicKeyComputed is not equal to r.PublicKey, it means there is a mismatch between the computed public key and the expected public key.
	if !r.PublicKey.Equal(PublicKeyComputed) {
		//YHat=r.ElGamalKNonce * r.ElGamal[r.SelfID()]
		YHat := r.ElGamalKNonce.Act(r.ElGamal[r.SelfID()])
		//  construct YHatProof
		YHatProof := zklog.NewProofMal(r.Group(), r.HashForID(r.SelfID()), zklog.Public{
			H: r.ElGamalKNonce.ActOnBase(),
			X: r.ElGamal[r.SelfID()],
			Y: YHat,
		}, zklog.Private{
			A: r.ElGamalKNonce,
			B: r.SecretElGamal,
		})
		// construct ChiProofs for each ChiCiphertext value using the proveNth function.
		ChiProofs := make(map[party.ID]*abortNth, r.N()-1)
		for _, j := range r.OtherPartyIDs() {
			chiCiphertext := r.ChiCiphertext[j][r.SelfID()] // D̂ᵢⱼ
			ChiProofs[j] = proveNth(r.HashForID(r.SelfID()), r.SecretPaillier, chiCiphertext)
		}

		//initiate a abort2 session  by broadcasting YHat, YHatProof, KProof, and ChiProofs using the broadcastAbort2 message.
		msg := &broadcastAbort2{
			YHat:      YHat,
			YHatProof: YHatProof,
			KProof:    proveNth(r.HashForID(r.SelfID()), r.SecretPaillier, r.K[r.SelfID()]),
			ChiProofs: ChiProofs,
		}
		if err := r.BroadcastMessage(out, msg); err != nil {
			return r, err
		}
		ChiAlphas := make(map[party.ID]curve.Scalar, r.N())
		for id, chiAlpha := range r.ChiShareAlpha {
			ChiAlphas[id] = r.Group().NewScalar().SetNat(chiAlpha.Mod1(r.Group().Order()))
		}
		return &abort2{
			presign7:  r,
			YHat:      map[party.ID]curve.Point{r.SelfID(): YHat},
			KShares:   map[party.ID]curve.Scalar{r.SelfID(): r.KShare},
			ChiAlphas: map[party.ID]map[party.ID]curve.Scalar{r.SelfID(): ChiAlphas},
		}, nil
	}

	preSignature := &ecdsa.PreSignature{
		ID:       presignatureID,
		R:        r.R,
		RBar:     party.NewPointMap(r.RBar),
		S:        party.NewPointMap(r.S), //转化为PointMap类型
		KShare:   r.KShare,
		ChiShare: r.ChiShare,
	}
	if r.Message == nil {
		return r.ResultRound(preSignature), nil
	}

	rSign1 := &sign1{
		Helper:       r.Helper,
		PublicKey:    r.PublicKey,
		Message:      r.Message,
		PreSignature: preSignature,
	}
	//return the result of the Finalize method called on rSign1.
	return rSign1.Finalize(out)
}

// MessageContent implements round.Round.
func (presign7) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast7) RoundNumber() round.Number { return 7 }

// BroadcastContent implements round.BroadcastRound.
func (r *presign7) BroadcastContent() round.BroadcastContent {
	return &broadcast7{
		S: r.Group().NewPoint(),
		//Proof: zkelog.Empty(r.Group()),
		Proof: &zkelog.Proofbuf{},
	}
}

// Number implements round.Round.
func (presign7) Number() round.Number { return 7 }
