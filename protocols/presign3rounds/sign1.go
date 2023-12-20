// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presign3rounds

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/pkg/ecdsa3rounds"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
)

var _ round.Round = (*sign1)(nil)

type sign1 struct {
	*round.Helper
	//*presign4
	//不能继承presign4，而是应该把sign2和abort2需要的数据传入进来
	//*presignRecord
	// PublicKey = X
	PublicKey curve.Point
	// Message = m
	Message []byte
	// PreSignature = (R, kᵢ, χᵢ)
	PreSignature *ecdsa3rounds.PreSignature3
}

// VerifyMessage implements round.Round.
func (r *sign1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *sign1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
func (r *sign1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// σᵢ = kᵢm+rχᵢ (mod q)
	SigmaShare := r.PreSignature.SignatureShare(r.Message)
	//broadcast SigmaShare value to all other parties using the broadcastSign2 message.
	err := r.BroadcastMessage(out, &broadcastSign2{
		Sigma: SigmaShare,
	})
	if err != nil {
		return r, err.(error)
	}

	return &sign2{
		sign1:       r,
		SigmaShares: map[party.ID]curve.Scalar{r.SelfID(): SigmaShare},
	}, nil
}

// MessageContent implements round.Round.
func (sign1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (sign1) Number() round.Number { return 1 }
