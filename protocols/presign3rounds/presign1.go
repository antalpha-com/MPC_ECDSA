// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presign3rounds

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/types"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pedersen"
	"MPC_ECDSA/pkg/pool"
	zkenc "MPC_ECDSA/pkg/zk/enc"
	"crypto/rand"
)

var _ round.Round = (*presign1)(nil)

type presign1 struct {
	*round.Helper
	// Pool allows us to parallelize certain operations
	Pool *pool.Pool

	// SecretECDSA = xᵢ
	SecretECDSA curve.Scalar
	// SecretElGamal = yᵢ
	SecretElGamal curve.Scalar
	// SecretPaillier = (pᵢ, qᵢ)
	SecretPaillier *paillier.SecretKey

	// PublicKey = X
	PublicKey curve.Point
	// ECDSA[j] = Xⱼ
	ECDSA map[party.ID]curve.Point
	// ElGamal[j] = Yⱼ
	ElGamal map[party.ID]curve.Point
	// Paillier[j] = Nⱼ
	Paillier map[party.ID]*paillier.PublicKey
	// Pedersen[j] = (Nⱼ,Sⱼ,Tⱼ)
	Pedersen map[party.ID]*pedersen.Parameters

	// Message is the message to be signed. If it is nil, a presignature is created.
	Message []byte
}

// VerifyMessage implements round.Round.
func (presign1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (presign1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
// Sample ki, γi ← Fq
// - Gi = enci(γi; νi)
// - Ki = enci(ki; ρi)
func (r *presign1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// γᵢ <- 𝔽,
	GammaShare := sample.Scalar(rand.Reader, r.Group())
	GammaShareInt := curve.MakeInt(GammaShare)
	// Gᵢ = Encᵢ(γᵢ;νᵢ)
	//G and GNonce are obtained by encrypting GammaShare using the Paillier encryption scheme with the public key associated with the current party r.SelfID().
	//G represents the encryption result, and GNonce is the nonce used during encryption.
	G, GNonce := r.Paillier[r.SelfID()].Enc(GammaShareInt)

	// kᵢ <- 𝔽,
	KShare := sample.Scalar(rand.Reader, r.Group())
	KShareInt := curve.MakeInt(KShare)
	// Kᵢ = Encᵢ(kᵢ;ρᵢ)
	K, KNonce := r.Paillier[r.SelfID()].Enc(KShareInt)

	presignatureID, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, err
	}
	commitmentID, decommitmentID, err := r.HashForID(r.SelfID()).Commit(presignatureID)
	if err != nil {
		return r, err
	}
	broadcastMsg := broadcast2{
		K:            K,
		G:            G,
		CommitmentID: commitmentID,
	}
	//The broadcastMsg is sent to all other parties using the BroadcastMessage method of the current round r with the output channel out.
	if err = r.BroadcastMessage(out, &broadcastMsg); err != nil {
		return r, err
	}
	otherIDs := r.OtherPartyIDs()
	//send messages to each of the other parties in parallel.
	errs := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		//For each party identified by j in otherIDs,
		//a zk proof is created using zkenc.NewProofMal
		//with the group, the hash function associated with the current party, and the public and private values required for the proof.
		j := otherIDs[i]
		kEncProof := zkenc.NewProofMal(r.Group(), r.HashForID(r.SelfID()), zkenc.Public{
			K:      K,
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zkenc.Private{
			K:   KShareInt,
			Rho: KNonce,
		})
		return r.SendMessage(out, &message2{KEncProof: kEncProof}, j)
	})
	for _, err := range errs {
		if err != nil {
			return r, err.(error)
		}
	}
	return &presign2{
		presign1:       r,
		K:              map[party.ID]*paillier.Ciphertext{r.SelfID(): K},
		G:              map[party.ID]*paillier.Ciphertext{r.SelfID(): G},
		GammaShare:     GammaShareInt,
		KShare:         KShare,
		KNonce:         KNonce,
		GNonce:         GNonce,
		PresignatureID: map[party.ID]types.RID{r.SelfID(): presignatureID},
		CommitmentID:   map[party.ID]hash.Commitment{},
		DecommitmentID: decommitmentID,
	}, nil
}

// MessageContent implements round.Round.
func (presign1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (presign1) Number() round.Number { return 1 }
