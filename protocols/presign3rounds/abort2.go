// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presign3rounds

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/party"
	zkaffg "MPC_ECDSA/pkg/zk/affg"
	zkdec "MPC_ECDSA/pkg/zk/dec"
	zkmulstar "MPC_ECDSA/pkg/zk/mulstar"
	"errors"
)

type broadcastAbort2 struct {
	round.NormalBroadcastContent
	// Dhat zkaffg proof
	ReChiProofMap    map[party.ID]*zkaffg.Proofbuf
	MulProofMap      map[party.ID]*zkmulstar.Proofbuf
	SigmaDecProofMap map[party.ID]*zkdec.Proofbuf
	HHatShare        *gmp_paillier.Ciphertext
	SigmaExpect      *gmp_paillier.Ciphertext
}

type abort2 struct {
	*sign2
	culprits []party.ID
}

// StoreBroadcastMessage function is a method of the abort1 struct.
// It is used to store and validate the broadcast message received during the abort1 round.
func (r *abort2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcastAbort2)
	//If the content is not of the expected type or is nil, return an ErrInvalidContent error.
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	record := r.PreSignature.Record
	for to, ChiProof := range body.ReChiProofMap {
		if !ChiProof.VerifyMal(r.Group(), r.HashForID(from), zkaffg.Public{
			Kv:       record.K[to],
			Dv:       record.ChiCiphertext[from][to],
			Fp:       record.ChiFs[from],
			Xp:       record.ECDSA.Points[from],
			Prover:   record.Paillier[from],
			Verifier: record.Paillier[to],
			Aux:      record.Pedersen[to],
		}) {
			r.culprits = append(r.culprits, from)
			return errors.New("failed to validate affg proof for Delta MtA")
		}
	}
	for to, MulProof := range body.MulProofMap {
		if !MulProof.VerifyMal(r.Group(), r.HashForID(from), zkmulstar.Public{
			C:        record.K[from],
			D:        body.HHatShare,
			X:        record.ECDSA.Points[from],
			Verifier: record.Paillier[to],
			Aux:      record.Pedersen[to],
		}) {
			r.culprits = append(r.culprits, from)
			return errors.New("failed to validate Mul* Proof for Hhati")
		}
	}

	for to, DecProof := range body.SigmaDecProofMap {
		if !DecProof.VerifyMal(r.Group(), r.HashForID(from), zkdec.Public{
			C:      body.SigmaExpect,
			X:      r.SigmaShares[from],
			Prover: record.Paillier[from],
			Aux:    record.Pedersen[to],
		}) {
			r.culprits = append(r.culprits, from)
			return errors.New("failed to validate dec Proof for deltai")
		}
	}
	return nil

}

// VerifyMessage implements round.Round.
func (abort2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (abort2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
func (r *abort2) Finalize(chan<- *round.Message) (round.Session, error) {
	return r.AbortRound(errors.New("abort2: detected culprit"), r.culprits...), nil
}

// MessageContent implements round.Round.
func (abort2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcastAbort2) RoundNumber() round.Number { return 8 }

// BroadcastContent implements round.BroadcastRound.
func (r *abort2) BroadcastContent() round.BroadcastContent { return &broadcastAbort2{} }

// Number implements round.Round.
func (abort2) Number() round.Number { return 8 }
