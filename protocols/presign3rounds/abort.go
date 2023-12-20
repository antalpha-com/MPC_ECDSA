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
	zkmul "MPC_ECDSA/pkg/zk/mul"
	"errors"
)

type broadcastAbort1 struct {
	round.NormalBroadcastContent
	// D zkaffg proof
	reDeltaProofMap   map[party.ID]*zkaffg.Proofbuf
	MulProof          *zkmul.Proofbuf
	deltaDecProofMap  map[party.ID]*zkdec.Proofbuf
	HShare            *gmp_paillier.Ciphertext
	deltaCipherexpect *gmp_paillier.Ciphertext
}

type abort1 struct {
	*presign4
	//HShareMap map[party.ID]*gmp_paillier.Ciphertext
	//reDeltaProofMaps map[party.ID]map[party.ID]*zkaffg.Proofbuf
	//MulProofs map[party.ID]*zkmul.Proofbuf
	//deltaDecProofMap map[party.ID]map[party.ID]*zkdec.Proofbuf

	culprits []party.ID
}

// StoreBroadcastMessage function is a method of the abort1 struct.
// It is used to store and validate the broadcast message received during the abort1 round.
func (r *abort1) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcastAbort1)
	//If the content is not of the expected type or is nil, return an ErrInvalidContent error.
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	for to, DeltaProof := range body.reDeltaProofMap {
		if !DeltaProof.VerifyMal(r.Group(), r.HashForID(from), zkaffg.Public{
			Kv:       r.K[to],
			Dv:       r.DeltaCiphertext[from][to],
			Fp:       r.DeltaFs[from],
			Xp:       r.BigGammaShare[from],
			Prover:   r.Paillier[from],
			Verifier: r.Paillier[to],
			Aux:      r.Pedersen[to],
		}) {
			r.culprits = append(r.culprits, from)
			return errors.New("failed to validate affg proof for Delta MtA")
		}
	}

	if !body.MulProof.VerifyMal(r.Group(), r.HashForID(from), zkmul.Public{
		X:      r.G[from],
		Y:      r.K[from],
		C:      body.HShare,
		Prover: r.Paillier[from],
	}) {
		r.culprits = append(r.culprits, from)
		return errors.New("failed to validate Mul Proof for Hi")
	}

	for to, DecProof := range body.deltaDecProofMap {
		if !DecProof.VerifyMal(r.Group(), r.HashForID(from), zkdec.Public{
			C:      body.deltaCipherexpect,
			X:      r.DeltaShares[from],
			Prover: r.Paillier[from],
			Aux:    r.Pedersen[to],
		}) {
			r.culprits = append(r.culprits, from)
			return errors.New("failed to validate dec Proof for deltai")
		}
	}
	return nil

}

// VerifyMessage implements round.Round.
func (abort1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (abort1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
func (r *abort1) Finalize(chan<- *round.Message) (round.Session, error) {
	return r.AbortRound(errors.New("abort1: detected culprit"), r.culprits...), nil
}

// MessageContent implements round.Round.
func (abort1) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcastAbort1) RoundNumber() round.Number { return 7 }

// BroadcastContent implements round.BroadcastRound.
func (r *abort1) BroadcastContent() round.BroadcastContent { return &broadcastAbort1{} }

// Number implements round.Round.
func (abort1) Number() round.Number { return 7 }
