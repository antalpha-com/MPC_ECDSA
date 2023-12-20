// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presign3rounds

import (
	"MPC_ECDSA/internal/mta"
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/types"
	"MPC_ECDSA/pkg/BigInt"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	zkaffg "MPC_ECDSA/pkg/zk/affg"
	zkenc "MPC_ECDSA/pkg/zk/enc"
	zklogstar "MPC_ECDSA/pkg/zk/logstar"
	"errors"
)

var _ round.Round = (*presign2)(nil)

type presign2 struct {
	*presign1

	// K[j] = Kⱼ = encⱼ(kⱼ)
	K map[party.ID]*paillier.Ciphertext
	// G[j] = Gⱼ = encⱼ(γⱼ)
	G map[party.ID]*paillier.Ciphertext

	// GammaShare = γᵢ <- 𝔽
	GammaShare *BigInt.Nat
	// KShare = kᵢ  <- 𝔽
	KShare curve.Scalar

	// KNonce = ρᵢ <- ℤₙ
	// used to encrypt Kᵢ = Encᵢ(kᵢ)
	KNonce *BigInt.Nat
	// GNonce = νᵢ <- ℤₙ
	// used to encrypt Gᵢ = Encᵢ(γᵢ)
	GNonce *BigInt.Nat

	// PresignatureID[j] = idⱼ
	PresignatureID map[party.ID]types.RID
	// CommitmentID[j] = Com(idⱼ)
	CommitmentID map[party.ID]hash.Commitment
	// DecommitmentID is the decommitment string for idᵢ
	DecommitmentID hash.Decommitment
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// K = Kᵢ
	K *paillier.Ciphertext
	// G = Gᵢ
	G *paillier.Ciphertext
	// CommitmentID is a commitment Pᵢ's contribution to the final presignature ID.
	CommitmentID hash.Commitment
}

type message2 struct {
	KEncProof *zkenc.Proofbuf
}

// RoundNumber implements round.Content.
func (message2) RoundNumber() round.Number { return 2 }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - store Kⱼ, Gⱼ
// CommitmentID.
func (r *presign2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if !r.Paillier[from].ValidateCiphertexts(body.K, body.G) {
		return round.ErrNilFields
	}

	if err := body.CommitmentID.Validate(); err != nil {
		return err
	}

	r.K[from] = body.K
	r.G[from] = body.G
	r.CommitmentID[from] = body.CommitmentID

	return nil
}

// VerifyMessage implements round.Round.
//
// - verify zkenc.
func (r *presign2) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if !body.KEncProof.VerifyMal(r.Group(), r.HashForID(from), zkenc.Public{
		K:      r.K[from],
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}) {
		return errors.New("failed to validate enc proof for K")
	}
	return nil
}

// StoreMessage implements round.Round.
func (presign2) StoreMessage(round.Message) error { return nil }

// Finalize function completes the second part of the presigning protocol,
// where each party generates the mta proofs, broadcasts messages to the other parties, and sends the respective messages to each party.
// It returns a new presign3rounds session that represents the next phase of the protocol.
func (r *presign2) Finalize(out chan<- *round.Message) (round.Session, error) {
	otherIDs := r.OtherPartyIDs()
	n := len(otherIDs)

	//BigGammaShare is computed as the scalar multiplication of γᵢ with the group's base point using the ActOnBase method.
	// Γᵢ = γᵢ⋅G，
	BigGammaShare := r.Group().NewScalar().SetNat(r.GammaShare.Mod1(r.Group().Order())).ActOnBase()

	//The mtaOut struct is defined to hold the output of the multiplicative to additive proofs for each party.
	type mtaOut struct {
		DeltaBeta  *BigInt.Nat
		DeltaD     *paillier.Ciphertext
		DeltaF     *paillier.Ciphertext
		DeltaProof *zkaffg.Proofbuf
		ChiBeta    *BigInt.Nat
		ChiD       *paillier.Ciphertext
		ChiF       *paillier.Ciphertext
		ChiProof   *zkaffg.Proofbuf
		ProofLog   *zklogstar.Proofbuf
	}

	mtaOuts := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]
		//the multiplicative to additive proofs are generated using the mta.ProveAffG functions.
		DeltaBeta, DeltaD, DeltaF, DeltaProof := mta.ProveAffG(r.Group(), r.HashForID(r.SelfID()),
			r.GammaShare, BigGammaShare, r.K[j],
			r.SecretPaillier, r.Paillier[j], r.Pedersen[j])

		ChiBeta, ChiD, ChiF, ChiProof := mta.ProveAffG(r.Group(), r.HashForID(r.SelfID()),
			curve.MakeInt(r.SecretECDSA), r.ECDSA[r.SelfID()], r.K[j],
			r.SecretPaillier, r.Paillier[j], r.Pedersen[j])

		proofLog := zklogstar.NewProofMal(r.Group(), r.HashForID(r.SelfID()), zklogstar.Public{
			C:      r.G[r.SelfID()],
			X:      BigGammaShare,
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zklogstar.Private{
			X:   r.GammaShare,
			Rho: r.GNonce,
		})

		return mtaOut{
			DeltaBeta:  DeltaBeta,
			DeltaD:     DeltaD,
			DeltaF:     DeltaF,
			DeltaProof: DeltaProof,
			ChiBeta:    ChiBeta,
			ChiD:       ChiD,
			ChiF:       ChiF,
			ChiProof:   ChiProof,
			ProofLog:   proofLog,
		}
	})

	//a map that store the paillier.Ciphertext values for each party's ChiD. [party ID][corresponding ciphertext]
	ChiCiphertext := make(map[party.ID]*paillier.Ciphertext, n)
	//a map that stores the BigInt.Nat values for each party's ChiBeta. [party ID][corresponding ChiBeta]
	ChiShareBeta := make(map[party.ID]*BigInt.Nat, n)
	//a map that store the paillier.Ciphertext values for each party's DeltaD,[party ID][corresponding ciphertext]
	DeltaCiphertext := make(map[party.ID]*paillier.Ciphertext, n)
	//a map that stores the BigInt.Nat values for each party's DeltaBeta. [party ID][corresponding DeltaBeta]
	DeltaShareBeta := make(map[party.ID]*BigInt.Nat, n)
	// FjiArray[j] = Fji
	FjiArray := make(map[party.ID]*paillier.Ciphertext, n)
	// FjiArray[j] = Fji
	FHatjiArray := make(map[party.ID]*paillier.Ciphertext, n)

	// p2p messages
	msgs := make(map[party.ID]*message3, n)
	for idx, mtaOutRaw := range mtaOuts {
		j := otherIDs[idx]
		m := mtaOutRaw.(mtaOut)
		DeltaShareBeta[j] = m.DeltaBeta
		DeltaCiphertext[j] = m.DeltaD
		ChiShareBeta[j] = m.ChiBeta
		ChiCiphertext[j] = m.ChiD
		FjiArray[j] = m.DeltaF
		FHatjiArray[j] = m.ChiF

		msgs[j] = &message3{
			DeltaCiphertext: DeltaCiphertext, //Dji
			ChiCiphertext:   ChiCiphertext,   //^Dji
			DeltaF:          m.DeltaF,
			DeltaProof:      m.DeltaProof,
			ChiF:            m.ChiF,
			ChiProof:        m.ChiProof,
			BigGammaShare:   BigGammaShare,
			ProofLog:        m.ProofLog,
		}
	}

	//broadcastMsg is sent to all other parties using the BroadcastMessage method of the current round r with the output channel out.
	broadcastMsg := broadcast3{
		DeltaCiphertext: DeltaCiphertext, //Dji
		ChiCiphertext:   ChiCiphertext,   //^Dji
	} //TODO:虽然这里广播也没关系啦，只有对应的j才能解密这个消息，但是会增加开销，之后改为全部蛋啵

	// 从i参与方广播
	if err := r.BroadcastMessage(out, &broadcastMsg); err != nil {
		return r, err
	}
	//send messages to each of the other parties.
	//For each party identified by id, the corresponding message is retrieved from msgs
	//and sent using the SendMessage method of the current round r with the output channel out
	for id, msg := range msgs {
		if err := r.SendMessage(out, msg, id); err != nil {
			return r, err
		}
	}

	//the function returns a new presign3 session with the updated values and state,
	//including the share values (DeltaShareBeta, ChiShareBeta) and the ciphertext values (DeltaCiphertext, ChiCiphertext).
	return &presign3{
		presign2:        r,
		DeltaShareBeta:  DeltaShareBeta,
		ChiShareBeta:    ChiShareBeta,
		DeltaCiphertext: map[party.ID]map[party.ID]*paillier.Ciphertext{r.SelfID(): DeltaCiphertext},
		ChiCiphertext:   map[party.ID]map[party.ID]*paillier.Ciphertext{r.SelfID(): ChiCiphertext},
		BigGammaShare:   map[party.ID]curve.Point{r.SelfID(): BigGammaShare},
		DeltaProofs:     map[party.ID]*zkaffg.Proofbuf{},
		ChiProofs:       map[party.ID]*zkaffg.Proofbuf{},
		DeltaFs:         map[party.ID]*paillier.Ciphertext{},
		ChiFs:           map[party.ID]*paillier.Ciphertext{},
		FjiArray:        FjiArray,
		FHatjiArray:     FHatjiArray,
	}, nil
}

// MessageContent implements round.Round.
func (r *presign2) MessageContent() round.Content {
	return &message2{
		KEncProof: &zkenc.Proofbuf{},
	}
}

// BroadcastContent implements round.BroadcastRound.
func (r *presign2) BroadcastContent() round.BroadcastContent {
	return &broadcast2{}
}

// Number implements round.Round.
func (presign2) Number() round.Number { return 2 }
