// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presign3rounds

import "C"
import (
	"MPC_ECDSA/internal/mta"
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/types"
	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/ecdsa3rounds"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	zkaffg "MPC_ECDSA/pkg/zk/affg"
	zkdec "MPC_ECDSA/pkg/zk/dec"
	zklogstar "MPC_ECDSA/pkg/zk/logstar"
	zkmul "MPC_ECDSA/pkg/zk/mul"
	"errors"
)

var _ round.Round = (*presign4)(nil)

type presign4 struct {
	*presign3
	// Γ = ∑ⱼ Γⱼ
	Gamma curve.Point
	// Δᵢ = kᵢ⋅Γ
	BigDeltaShare map[party.ID]curve.Point
	// DeltaShareAlpha[j] = αᵢⱼ
	DeltaShareAlpha map[party.ID]*BigInt.Nat
	// ChiShareAlpha[j] = α̂ᵢⱼ
	ChiShareAlpha map[party.ID]*BigInt.Nat
	// DeltaShares[j] = δⱼ 后面会用到
	DeltaShares map[party.ID]curve.Scalar
	// ChiShare = χᵢ
	ChiShare curve.Scalar
	// DeltaShareNat = δi
	DeltaShareNat *BigInt.Nat
}

type message4 struct {
	// δᵢ = γᵢ kᵢ + ∑ⱼ αᵢⱼ + βᵢⱼ
	DeltaShare curve.Scalar
	// Δᵢ = kᵢ⋅Γ
	BigDeltaShare curve.Point
	// log* proof
	BigDeltalogProof *zklogstar.Proofbuf
}

type broadcast4 struct {
	round.NormalBroadcastContent
	DecommitmentID hash.Decommitment
	PresignatureID types.RID
}

// RoundNumber implements round.Content.
func (message4) RoundNumber() round.Number { return 4 }

func (r *presign4) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast4)
	if !ok || body == nil {
		return round.ErrInvalidContent
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
	r.PresignatureID[from] = body.PresignatureID
	return nil
}

// VerifyMessage implements round.Round.
//
// - verify log*.
func (r *presign4) VerifyMessage(msg round.Message) error {
	from := msg.From
	to := msg.To
	body, ok := msg.Content.(*message4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if !body.BigDeltalogProof.VerifyMal(r.Group(), r.HashForID(from), zklogstar.Public{
		C:      r.K[from],
		X:      body.BigDeltaShare,
		G:      r.Gamma,
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}) {
		return errors.New("failed to validate log* proof for BigDeltaShare")
	}

	return nil
}

// StoreMessage implements round.Round.
func (r *presign4) StoreMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*message4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// store variables
	r.DeltaShares[from] = body.DeltaShare
	r.BigDeltaShare[from] = body.BigDeltaShare
	return nil
}

// Finalize implements round.Round
//
// - compute δ = ∑ⱼ δⱼ
// - verify δ⋅G ?= ∑ⱼΔⱼ
// --- fail
// - store result
// Finalize method calculates the final values Gamma and BigDeltaShare based on the collected BigGammaShare values and broadcasts them along with the corresponding proof to the other parties.
func (r *presign4) Finalize(out chan<- *round.Message) (round.Session, error) {
	// δ = ∑ⱼ δⱼ
	Delta := r.Group().NewScalar()
	for _, Deltaj := range r.DeltaShares {
		Delta = Delta.Add(Deltaj)
	}

	// δ⋅G
	BigDeltaExpected := Delta.ActOnBase()

	// ∑ⱼΔⱼ
	BigDeltaActual := r.Group().NewPoint()
	for _, BigDeltaJ := range r.BigDeltaShare {
		BigDeltaActual = BigDeltaActual.Add(BigDeltaJ)
	}

	// verify δ⋅G ?= ∑ⱼΔⱼ
	// if fail, compute proof and broadcast
	if !BigDeltaActual.Equal(BigDeltaExpected) {
		// 这里生成prove而不是直接verify
		otherIDs := r.OtherPartyIDs()
		// re-prove D zkaffg proof
		reDeltaProofs := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
			j := otherIDs[i]
			//the multiplicative to additive proofs are generated using the mta.ProveAffG functions.
			_, _, _, DeltaProof := mta.ProveAffG(r.Group(), r.HashForID(r.SelfID()),
				r.GammaShare, r.BigGammaShare[r.SelfID()], r.K[j],
				r.SecretPaillier, r.Paillier[j], r.Pedersen[j])

			return DeltaProof
		})
		// 组成map
		reDeltaProofMap := make(map[party.ID]*zkaffg.Proofbuf)
		for idx, reDeltaProof := range reDeltaProofs {
			j := otherIDs[idx]
			reDeltaProofMap[j] = reDeltaProof.(*zkaffg.Proofbuf)
		}

		//prove zkmul
		prover := r.Paillier[r.SelfID()]
		x := r.GammaShare
		X, rhoX := prover.Enc(x)

		KShareInt := curve.MakeInt(r.KShare)
		Y, _ := prover.Enc(KShareInt)
		HShare := Y.Clone().Mul(prover, x)
		rho := HShare.Randomize(prover, nil)

		public := zkmul.Public{
			X:      X,
			Y:      Y,
			C:      HShare,
			Prover: prover,
		}
		private := zkmul.Private{
			X:    x,
			Rho:  rho,
			RhoX: rhoX,
		}

		MulProof := zkmul.NewProofMal(r.Group(), r.HashForID(r.SelfID()), public, private)

		// compute Hi + ∑(Dij+Fji)
		deltaCipherexpect := HShare
		// Dij = r.DeltaCiphertext[j][r.SelfID()]
		for _, j := range r.OtherPartyIDs() {
			Dij := r.DeltaCiphertext[j][r.SelfID()]
			Fji := r.FjiArray[j]
			// 这里根据ciphertext.go,应该是add而不是mul
			deltaCipherexpect = deltaCipherexpect.Add(r.Paillier[r.SelfID()], Dij)
			deltaCipherexpect = deltaCipherexpect.Add(r.Paillier[r.SelfID()], Fji)
		}

		// prove zkdec
		deltaDecProofs := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
			j := otherIDs[i]
			deltaDecProof := zkdec.NewProofMal(r.Group(), r.HashForID(r.SelfID()), zkdec.Public{
				C:      deltaCipherexpect,
				X:      r.DeltaShares[r.SelfID()],
				Prover: r.Paillier[r.SelfID()],
				Aux:    r.Pedersen[j],
			}, zkdec.Private{
				Y:   r.DeltaShareNat,
				Rho: new(BigInt.Nat).SetUint64(0x1122),
			})
			return deltaDecProof
		})

		// 组成map
		deltaDecProofMap := make(map[party.ID]*zkdec.Proofbuf)
		for idx, deltaDecProof := range deltaDecProofs {
			j := otherIDs[idx]
			deltaDecProofMap[j] = deltaDecProof.(*zkdec.Proofbuf)
		}
		// 消息广播出去
		broadcastMsg := broadcastAbort1{
			reDeltaProofMap:   reDeltaProofMap,
			MulProof:          MulProof,
			deltaDecProofMap:  deltaDecProofMap,
			HShare:            HShare,
			deltaCipherexpect: deltaCipherexpect,
		}
		if err := r.BroadcastMessage(out, &broadcastMsg); err != nil {
			return r, err
		}
		return &abort1{
			presign4: r,
		}, nil
	}

	//If BigDeltaActual is equal to BigDeltaExpected
	// δ⁻¹
	DeltaInv := r.Group().NewScalar().Set(Delta).Invert()

	// R = [δ⁻¹] Γ
	R := DeltaInv.Act(r.Gamma)

	//presignatureID is computed by performing XOR operation on all id values in r.PresignatureID.
	presignatureID := types.EmptyRID()
	for _, id := range r.PresignatureID {
		presignatureID.XOR(id)
	}

	record := &ecdsa3rounds.PresignRecord{
		SecretECDSA:    r.SecretECDSA,
		ECDSA:          party.NewPointMap(r.ECDSA),
		K:              r.K,
		SecretPaillier: r.SecretPaillier,
		Paillier:       r.Paillier,
		Pedersen:       r.Pedersen,
		ChiCiphertext:  r.ChiCiphertext,
		FHatjiArray:    r.FHatjiArray,
		ChiFs:          r.ChiFs,
	}
	preSignature := &ecdsa3rounds.PreSignature3{
		ID:       presignatureID,
		R:        R,
		KShare:   r.KShare,
		ChiShare: r.ChiShare,
		Record:   record,
	}
	// presign end
	if r.Message == nil {
		return r.ResultRound(preSignature), nil
	}

	// can sign message
	rSign1 := &sign1{
		Helper:       r.Helper,
		PublicKey:    r.PublicKey,
		Message:      r.Message,
		PreSignature: preSignature,
	}
	//return the result of the Finalize method called on rSign1.
	//return rSign1.Finalize(out)
	return rSign1, nil
}

// Number implements round.Round.
func (presign4) Number() round.Number { return 4 }

// MessageContent implements round.Round.
func (r *presign4) MessageContent() round.Content {
	return &message4{
		DeltaShare:    r.Group().NewScalar(),
		BigDeltaShare: r.Group().NewPoint(),
	}
}

// BroadcastContent implements round.BroadcastRound.
func (r *presign4) BroadcastContent() round.BroadcastContent {
	return &broadcast4{}
}

// RoundNumber implements round.Content.
func (broadcast4) RoundNumber() round.Number { return 4 }
