// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presign3rounds

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/pkg/BigInt"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	zkaffg "MPC_ECDSA/pkg/zk/affg"
	zklogstar "MPC_ECDSA/pkg/zk/logstar"
	"errors"
	"fmt"
)

var _ round.Round = (*presign3)(nil)

type presign3 struct {
	*presign2

	// DeltaShareBeta[j] = βᵢⱼ
	DeltaShareBeta map[party.ID]*BigInt.Nat
	// ChiShareBeta[j] = β̂ᵢⱼ
	ChiShareBeta map[party.ID]*BigInt.Nat

	// DeltaCiphertext[j][k] = Dₖⱼ
	DeltaCiphertext map[party.ID]map[party.ID]*paillier.Ciphertext
	// ChiCiphertext[j][k] = D̂ₖⱼ
	ChiCiphertext map[party.ID]map[party.ID]*paillier.Ciphertext
	// BigGammaShare[j] = Γⱼ = [γⱼ]•G
	BigGammaShare map[party.ID]curve.Point
	// D affg proof
	DeltaProofs map[party.ID]*zkaffg.Proofbuf
	// D-hat affg proof
	ChiProofs map[party.ID]*zkaffg.Proofbuf
	// DeltaFs[j] = Fij
	DeltaFs map[party.ID]*paillier.Ciphertext
	// ChiFs[j] = Fhatij
	ChiFs map[party.ID]*paillier.Ciphertext
	// FjiArray[j] = Fji
	FjiArray map[party.ID]*paillier.Ciphertext
	//FHatjiArray = FHat_ji
	FHatjiArray map[party.ID]*paillier.Ciphertext
}

type broadcast3 struct {
	round.NormalBroadcastContent
	// DeltaCiphertext[k] = Dₖⱼ
	DeltaCiphertext map[party.ID]*paillier.Ciphertext
	// ChiCiphertext[k] = D̂ₖⱼ
	ChiCiphertext map[party.ID]*paillier.Ciphertext
	//BigGammaShare curve.Point
}

type message3 struct {
	DeltaCiphertext map[party.ID]*paillier.Ciphertext // DeltaCiphertext[k] = Dₖⱼ
	ChiCiphertext   map[party.ID]*paillier.Ciphertext // ChiCiphertext[k] = D̂ₖⱼ
	DeltaF          *paillier.Ciphertext              // DeltaF = Fᵢⱼ
	DeltaProof      *zkaffg.Proofbuf
	ChiF            *paillier.Ciphertext // ChiF = F̂ᵢⱼ
	ChiProof        *zkaffg.Proofbuf
	BigGammaShare   curve.Point
	ProofLog        *zklogstar.Proofbuf
}

// RoundNumber implements round.Content.
func (message3) RoundNumber() round.Number { return 3 }

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *presign3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.DeltaCiphertext == nil || body.ChiCiphertext == nil {
		return round.ErrNilFields
	}

	for _, id := range r.PartyIDs() {
		if id == from {
			continue
		}
		DeltaCiphertext, ChiCiphertext := body.DeltaCiphertext[id], body.ChiCiphertext[id]
		if !r.Paillier[id].ValidateCiphertexts(DeltaCiphertext, ChiCiphertext) {
			return errors.New("received invalid ciphertext")
		}
	}

	// Dij = r.DeltaCiphertext[j]
	r.DeltaCiphertext[from] = body.DeltaCiphertext
	r.ChiCiphertext[from] = body.ChiCiphertext
	//r.BigGammaShare[from] = body.BigGammaShare
	return nil
}

// VerifyMessage implements round.Round.
// - verify before store
// - verify zkaffg, log*
func (r *presign3) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	zkPublic := zkaffg.Public{
		Kv:       r.K[to],
		Dv:       body.DeltaCiphertext[to],
		Fp:       body.DeltaF,
		Xp:       body.BigGammaShare,
		Prover:   r.Paillier[from],
		Verifier: r.Paillier[to],
		Aux:      r.Pedersen[to],
	}
	if !body.DeltaProof.VerifyMal(r.Group(), r.HashForID(from), zkPublic) {
		return errors.New("failed to validate affg proof for Delta MtA")
	}

	if !body.ChiProof.VerifyMal(r.Group(), r.HashForID(from), zkaffg.Public{
		Kv:       r.K[to],
		Dv:       r.ChiCiphertext[from][to],
		Fp:       body.ChiF,
		Xp:       r.ECDSA[from],
		Prover:   r.Paillier[from],
		Verifier: r.Paillier[to],
		Aux:      r.Pedersen[to],
	}) {
		return errors.New("failed to validate affg proof for Chi MtA")
	}

	if !body.ProofLog.VerifyMal(r.Group(), r.HashForID(from), zklogstar.Public{
		C:      r.G[from],
		X:      body.BigGammaShare,
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}) {
		return errors.New("failed to validate log* proof for BigGammaShare")
	}

	return nil
}

// StoreMessage implements round.Round.
func (r *presign3) StoreMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*message3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	r.DeltaCiphertext[from] = body.DeltaCiphertext
	r.ChiCiphertext[from] = body.ChiCiphertext
	r.DeltaFs[from] = body.DeltaF
	r.DeltaProofs[from] = body.DeltaProof
	r.ChiFs[from] = body.ChiF
	r.ChiProofs[from] = body.ChiProof
	r.BigGammaShare[from] = body.BigGammaShare

	return nil
}

// Finalize implements round.Round
//
// - Decrypt MtA shares,
// - save αᵢⱼ, α̂ᵢⱼ.
// - Γ = ∑ⱼ Γⱼ
// - Δᵢ = [kᵢ]Γ
// - δᵢ = γᵢ kᵢ + ∑ⱼ αᵢⱼ + βᵢⱼ
// - χᵢ = xᵢ kᵢ + ∑ⱼ α̂ᵢⱼ + β̂ᵢⱼ
// - Ẑⱼ, b̂ⱼ
// Finalize method performs the computations and message exchange necessary to proceed to the next round of the presigning protocol.
func (r *presign3) Finalize(out chan<- *round.Message) (round.Session, error) {
	//Gamma is computed as the sum of all GammaJ values in r.BigGammaShare, where GammaJ is a group point.
	// Γ = ∑ⱼ Γⱼ
	Gamma := r.Group().NewPoint()
	for _, GammaJ := range r.BigGammaShare {
		Gamma = Gamma.Add(GammaJ)
	}

	// Δᵢ = kᵢ⋅Γ
	BigDeltaShare := r.KShare.Act(Gamma)

	var (
		culprits []party.ID //track any party j whose alpha shares fail to decrypt.
		err      error
	)

	// 先算自己本地的那部分
	// δᵢ = γᵢ kᵢ
	KShareInt := curve.MakeInt(r.KShare) //the party's own share of the secret kᵢ
	// χᵢ = xᵢ kᵢ
	ChiShare := new(BigInt.Nat).Mul(curve.MakeInt(r.SecretECDSA), KShareInt, -1)

	DeltaShare := new(BigInt.Nat).Mul(r.GammaShare, KShareInt, -1)

	//set maps DeltaSharesAlpha and ChiSharesAlpha to store the decrypted values of αᵢⱼ and α̂ᵢⱼ respectively, for each party j.
	DeltaSharesAlpha := make(map[party.ID]*BigInt.Nat, r.N())
	ChiSharesAlpha := make(map[party.ID]*BigInt.Nat, r.N())

	// compute mta result
	for _, j := range r.OtherPartyIDs() {
		// j参与方发给我的
		// αᵢⱼ
		DeltaSharesAlpha[j], err = r.SecretPaillier.Dec(r.DeltaCiphertext[j][r.SelfID()])
		// 解密失败说明j参与方是坏人
		if err != nil {
			culprits = append(culprits, j)
			continue
		}
		// α̂ᵢⱼ
		ChiSharesAlpha[j], err = r.SecretPaillier.Dec(r.ChiCiphertext[j][r.SelfID()])
		if err != nil {
			culprits = append(culprits, j)
			continue
		}
		//δᵢ += αᵢⱼ + βᵢⱼ
		DeltaShare.Add(DeltaShare, DeltaSharesAlpha[j], -1)
		DeltaShare.Add(DeltaShare, r.DeltaShareBeta[j], -1)

		// χᵢ += α̂ᵢⱼ + β̂ᵢⱼ
		ChiShare.Add(ChiShare, ChiSharesAlpha[j], -1)
		ChiShare.Add(ChiShare, r.ChiShareBeta[j], -1)
	}
	DeltaShareScalar := r.Group().NewScalar().SetNat(DeltaShare.Mod1(r.Group().Order()))

	//If any culprits are found, indicating decryption failures, the method aborts the round and returns an error.
	if culprits != nil {
		return r.AbortRound(fmt.Errorf("failed to decrypt alpha shares for mta"), culprits...), nil
	}
	msgs := make(map[party.ID]*message4, len(r.OtherPartyIDs()))
	for _, j := range r.OtherPartyIDs() {
		BigDeltalogProof := zklogstar.NewProofMal(r.Group(), r.HashForID(r.SelfID()), zklogstar.Public{
			C:      r.K[r.SelfID()],
			X:      BigDeltaShare,
			G:      Gamma, //这里的基不能用默认的G，而是用Gamma
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zklogstar.Private{
			X:   KShareInt,
			Rho: r.KNonce,
		})
		msgs[j] = &message4{
			DeltaShare:       DeltaShareScalar,
			BigDeltaShare:    BigDeltaShare,
			BigDeltalogProof: BigDeltalogProof,
		}
		if err := r.SendMessage(out, msgs[j], j); err != nil {
			return r, err
		}
	}

	broadcastMsg := &broadcast4{
		PresignatureID: r.PresignatureID[r.SelfID()],
		DecommitmentID: r.DecommitmentID,
	}
	if err := r.BroadcastMessage(out, broadcastMsg); err != nil {
		return r, err
	}

	return &presign4{
		presign3:        r,
		Gamma:           Gamma,
		BigDeltaShare:   map[party.ID]curve.Point{r.SelfID(): BigDeltaShare},
		DeltaShareAlpha: DeltaSharesAlpha,
		ChiShareAlpha:   ChiSharesAlpha,
		DeltaShares:     map[party.ID]curve.Scalar{r.SelfID(): DeltaShareScalar},
		ChiShare:        r.Group().NewScalar().SetNat(ChiShare.Mod1(r.Group().Order())),
		DeltaShareNat:   DeltaShare,
	}, nil
}

// Number implements round.Round.
func (presign3) Number() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *presign3) BroadcastContent() round.BroadcastContent { return &broadcast3{} }

// BroadcastData implements broadcast.Broadcaster.
func (m broadcast3) BroadcastData() []byte {
	h := hash.New()
	ids := make([]party.ID, 0, len(m.DeltaCiphertext))
	for id := range m.DeltaCiphertext {
		ids = append(ids, id)
	}
	sortedIDs := party.NewIDSlice(ids)
	for _, id := range sortedIDs {
		_ = h.WriteAny(id, m.DeltaCiphertext[id], m.ChiCiphertext[id])
	}
	return h.Sum()
}

// MessageContent implements round.Round.
func (r *presign3) MessageContent() round.Content {
	return &message3{
		BigGammaShare: r.Group().NewPoint(),
	}
}
