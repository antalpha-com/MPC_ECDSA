package presign

import (
	"errors"
	"fmt"

	"MPC_ECDSA/internal/elgamal"
	"MPC_ECDSA/internal/round"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	zkaffg "MPC_ECDSA/pkg/zk/affg"
	zkaffp "MPC_ECDSA/pkg/zk/affp"

	"MPC_ECDSA/pkg/BigInt"
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
}

type broadcast3 struct {
	round.NormalBroadcastContent
	// DeltaCiphertext[k] = Dₖⱼ
	DeltaCiphertext map[party.ID]*paillier.Ciphertext
	// ChiCiphertext[k] = D̂ₖⱼ
	ChiCiphertext map[party.ID]*paillier.Ciphertext
}

type message3 struct {
	DeltaF     *paillier.Ciphertext // DeltaF = Fᵢⱼ
	DeltaProof *zkaffp.Proofbuf
	ChiF       *paillier.Ciphertext // ChiF = F̂ᵢⱼ
	ChiProof   *zkaffg.Proofbuf
}

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

	r.DeltaCiphertext[from] = body.DeltaCiphertext
	r.ChiCiphertext[from] = body.ChiCiphertext
	return nil
}

// VerifyMessage implements round.Round.
//
// - verify zkaffg, zkaffp.
func (r *presign3) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if !body.DeltaProof.VerifyMal(r.Group(), r.HashForID(from), zkaffp.Public{
		Kv:       r.K[to],
		Dv:       r.DeltaCiphertext[from][to],
		Fp:       body.DeltaF,
		Xp:       r.G[from],
		Prover:   r.Paillier[from],
		Verifier: r.Paillier[to],
		Aux:      r.Pedersen[to],
	}) {
		return errors.New("failed to validate affp proof for Delta MtA")
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

	return nil
}

// StoreMessage implements round.Round.
func (presign3) StoreMessage(round.Message) error { return nil }

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
	// δᵢ = γᵢ kᵢ
	KShareInt := curve.MakeInt(r.KShare) //the party's own share of the secret kᵢ
	DeltaShare := new(BigInt.Nat).Mul(r.GammaShare, KShareInt, -1)
	//set maps DeltaSharesAlpha and ChiSharesAlpha to store the decrypted values of αᵢⱼ and α̂ᵢⱼ respectively, for each party j.
	DeltaSharesAlpha := make(map[party.ID]*BigInt.Nat, r.N())
	ChiSharesAlpha := make(map[party.ID]*BigInt.Nat, r.N())

	// χᵢ = xᵢ kᵢ
	ChiShare := new(BigInt.Nat).Mul(curve.MakeInt(r.SecretECDSA), KShareInt, -1)

	var (
		culprits []party.ID //track any party j whose alpha shares fail to decrypt.
		err      error
	)
	// Paillier decryption
	for _, j := range r.OtherPartyIDs() {
		//update DeltaShare and ChiShare by subtracting the decrypted values AlphaShares[j] and BetaShares[j] respectively.
		// αᵢⱼ
		DeltaSharesAlpha[j], err = r.SecretPaillier.Dec(r.DeltaCiphertext[j][r.SelfID()])
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
	//If any culprits are found, indicating decryption failures, the method aborts the round and returns an error.
	if culprits != nil {
		return r.AbortRound(fmt.Errorf("failed to decrypt alpha shares for mta"), culprits...), nil
	}

	// ElGamalChi = Ẑⱼ = (b̂ⱼ⋅G, χᵢ+b̂ⱼ⋅Yᵢ)
	// ElGamalChiNonce = b̂ⱼ
	ElGamalChi, ElGamalChiNonce := elgamal.Encrypt(r.ElGamal[r.SelfID()], r.Group().NewScalar().SetNat(ChiShare.Mod1(r.Group().Order())))

	DeltaShareScalar := r.Group().NewScalar().SetNat(DeltaShare.Mod1(r.Group().Order()))

	msg := &broadcast4{
		DeltaShare: DeltaShareScalar,
		ElGamalChi: ElGamalChi,
	}
	//BroadcastMessage
	if err = r.BroadcastMessage(out, msg); err != nil {
		return r, err
	}

	return &presign4{
		presign3:        r,
		DeltaShareAlpha: DeltaSharesAlpha,
		ChiShareAlpha:   ChiSharesAlpha,
		ElGamalChiNonce: ElGamalChiNonce,
		ElGamalChi:      map[party.ID]*elgamal.Ciphertext{r.SelfID(): ElGamalChi},
		DeltaShares:     map[party.ID]curve.Scalar{r.SelfID(): DeltaShareScalar},
		ChiShare:        r.Group().NewScalar().SetNat(ChiShare.Mod1(r.Group().Order())),
	}, nil
}

// RoundNumber implements round.Content.
func (message3) RoundNumber() round.Number { return 3 }

// MessageContent implements round.Round.
func (r *presign3) MessageContent() round.Content {
	return &message3{
		//ChiProof: zkaffg.Empty(r.Group())
		ChiProof: &zkaffg.Proofbuf{},
	}
}

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (presign3) BroadcastContent() round.BroadcastContent { return &broadcast3{} }

// Number implements round.Round.
func (presign3) Number() round.Number { return 3 }

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
