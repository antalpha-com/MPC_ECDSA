package presign

import (
	"crypto/rand"

	"MPC_ECDSA/internal/elgamal"
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/types"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pedersen"
	"MPC_ECDSA/pkg/pool"
	zkencelg "MPC_ECDSA/pkg/zk/encelg"
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

// Finalize implements round.Round
//
// - sample kᵢ, γᵢ <- 𝔽,
// - Γᵢ = [γᵢ]⋅G
// - Gᵢ = Encᵢ(γᵢ;νᵢ)
// - Kᵢ = Encᵢ(kᵢ;ρᵢ)
//
// NOTE
// The protocol instructs us to broadcast Kᵢ and Gᵢ, but the protocol we implement
// cannot handle identify aborts since we are in a point to point model.
// We do as described in [LN18].
// In the next round, we send a hash of all the {Kⱼ,Gⱼ}ⱼ.
// In two rounds, we compare the hashes received and if they are different then we abort.

// Finalize function completes the first part of the presigning protocol,
//where each party generates its own encrypted values, creates a zero-knowledge proof, and broadcasts the necessary messages to the other parties.
//It returns a new presign2 session that represents the next phase of the protocol.
func (r *presign1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// γᵢ <- 𝔽,
	GammaShare := sample.Scalar(rand.Reader, r.Group())
	// Gᵢ = Encᵢ(γᵢ;νᵢ)
	//G and GNonce are obtained by encrypting GammaShare using the Paillier encryption scheme with the public key associated with the current party r.SelfID().
	//G represents the encryption result, and GNonce is the nonce used during encryption.
	G, GNonce := r.Paillier[r.SelfID()].Enc(curve.MakeInt(GammaShare))

	// kᵢ <- 𝔽,
	KShare := sample.Scalar(rand.Reader, r.Group())
	KShareInt := curve.MakeInt(KShare)
	// Kᵢ = Encᵢ(kᵢ;ρᵢ)
	K, KNonce := r.Paillier[r.SelfID()].Enc(KShareInt)

	// Zᵢ = (bᵢ⋅G, kᵢ⋅G+bᵢ⋅Yᵢ),
	//ElGamalK and ElGamalNonce are obtained by encrypting KShare using the ElGamal encryption scheme with the ElGamal public key associated with the current party
	ElGamalK, ElGamalNonce := elgamal.Encrypt(r.ElGamal[r.SelfID()], KShare)

	presignatureID, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, err
	}
	commitmentID, decommitmentID, err := r.HashForID(r.SelfID()).Commit(presignatureID)
	if err != nil {
		return r, err
	}

	otherIDs := r.OtherPartyIDs()
	broadcastMsg := broadcast2{
		K:            K,
		G:            G,
		Z:            ElGamalK,
		CommitmentID: commitmentID,
	}
	//The broadcastMsg is sent to all other parties using the BroadcastMessage method of the current round r with the output channel out.
	if err = r.BroadcastMessage(out, &broadcastMsg); err != nil {
		return r, err
	}

	//send messages to each of the other parties in parallel.
	errs := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		//For each party identified by j in otherIDs,
		//a zk proof is created using zkencelg.NewProofMal
		//with the group, the hash function associated with the current party, and the public and private values required for the proof.
		j := otherIDs[i]
		proof := zkencelg.NewProofMal(r.Group(), r.HashForID(r.SelfID()), zkencelg.Public{
			C:      K,
			A:      r.ElGamal[r.SelfID()],
			B:      ElGamalK.L,
			X:      ElGamalK.M,
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zkencelg.Private{
			X:   KShareInt,
			Rho: KNonce,
			A:   r.SecretElGamal,
			B:   ElGamalNonce,
		})
		//sent  message to party j with the output channel out.
		return r.SendMessage(out, &message2{Proof: proof}, j)
	})
	for _, err := range errs {
		if err != nil {
			return r, err.(error)
		}
	}
	//return a new presign2 session with the updated values and state
	return &presign2{
		presign1:       r,
		K:              map[party.ID]*paillier.Ciphertext{r.SelfID(): K},
		G:              map[party.ID]*paillier.Ciphertext{r.SelfID(): G},
		GammaShare:     curve.MakeInt(GammaShare),
		KShare:         KShare,
		KNonce:         KNonce,
		GNonce:         GNonce,
		ElGamalKNonce:  ElGamalNonce,
		ElGamalK:       map[party.ID]*elgamal.Ciphertext{r.SelfID(): ElGamalK},
		PresignatureID: map[party.ID]types.RID{r.SelfID(): presignatureID},
		CommitmentID:   map[party.ID]hash.Commitment{},
		DecommitmentID: decommitmentID,
	}, nil
}

// MessageContent implements round.Round.
func (presign1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (presign1) Number() round.Number { return 1 }
