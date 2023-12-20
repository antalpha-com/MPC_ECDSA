package keygen

import (
	"errors"

	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/types"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/polynomial"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pedersen"
	zkmod "MPC_ECDSA/pkg/zk/mod"
	zkprm "MPC_ECDSA/pkg/zk/prm"
	"MPC_ECDSA/protocols/config"

	log "github.com/sirupsen/logrus"
)

var _ round.Round = (*round4)(nil)

type round4 struct {
	*round3

	// RID = ⊕ⱼ RIDⱼ
	// Random ID generated by taking the XOR of all ridᵢ
	RID types.RID
	// ChainKey is a sequence of random bytes agreed upon together
	ChainKey types.RID
}

type message4 struct {
	// Share = Encᵢ(x) is the encryption of the receivers share
	Share *paillier.Ciphertext
}

type broadcast4 struct {
	round.NormalBroadcastContent
	Mod *zkmod.Proofbuf
	Prm *zkprm.Proofbuf
}

// StoreBroadcastMessage implements round.BroadcastRound.
// verify the proofs of generating/updating the key
// - verify Mod, Prm proof for N
func (r *round4) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// verify zkmod
	if !body.Mod.VerifyMal(zkmod.Public{N: r.NModulus[from]}, r.HashForID(from), r.Pool) {
		log.Errorln("failed to validate mod proof")
		return errors.New("failed to validate mod proof")
	}

	// verify zkprm
	if !body.Prm.VerifyMal(zkprm.Public{N: r.NModulus[from], S: r.S[from], T: r.T[from]}, r.HashForID(from), r.Pool) {
		log.Errorln("failed to validate prm proof")
		return errors.New("failed to validate prm proof")
	}
	return nil
}

// VerifyMessage implements round.Round.
//
// - verify validity of share ciphertext.
func (r *round4) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message4)
	if !ok || body == nil {
		log.Errorln("fail to get body")
		return round.ErrInvalidContent
	}

	if !r.PaillierPublic[msg.To].ValidateCiphertexts(body.Share) {
		log.Errorln("fail to ValidateCiphertexts")
		return errors.New("invalid ciphertext")
	}

	return nil
}

// StoreMessage implements round.Round.
//
// Since this message is only intended for us, we need to do the VSS verification here.
// - check that the decrypted share did not overflow.
// - check VSS condition.
// - save share.
func (r *round4) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*message4)

	// decrypt share
	DecryptedShare, err := r.PaillierSecret.Dec(body.Share)
	if err != nil {
		return err
	}
	Share := r.Group().NewScalar().SetNat(DecryptedShare.Mod1(r.Group().Order()))
	if DecryptedShare.Eq(curve.MakeInt(Share)) != 1 {
		return errors.New("decrypted share is not in correct range")
	}

	// verify share with VSS
	ExpectedPublicShare := r.VSSPolynomials[from].Evaluate(r.SelfID().Scalar(r.Group())) // 别人的Fⱼ(x_i)
	PublicShare := Share.ActOnBase()
	// X == Fⱼ(i)
	if !PublicShare.Equal(ExpectedPublicShare) {
		return errors.New("failed to validate VSS share")
	}

	r.ShareReceived[from] = Share
	return nil
}

// Finalize implements round.Round
// - sum of all received shares
// - compute group public key and individual public keys
// - recompute config SSID
// - validate Config
// - write new ssid hash to old hash state
// - create proof of knowledge of secret.
func (r *round4) Finalize(out chan<- *round.Message) (round.Session, error) {
	// UpdatedSecretECDSA represents the updated secret value for ECDSA.
	UpdatedSecretECDSA := r.Group().NewScalar()
	//If there is a previous secret value, set UpdatedSecretECDSA to its value.
	if r.PreviousSecretECDSA != nil {
		UpdatedSecretECDSA.Set(r.PreviousSecretECDSA)
	}
	// Iterate through each party ID in r.PartyIDs().
	// Add the share received from each party to UpdatedSecretECDSA.
	for _, j := range r.PartyIDs() {
		UpdatedSecretECDSA.Add(r.ShareReceived[j]) //F(x_i)=∑fⱼ(x_i)
	}

	// ShamirPublicPolynomials is a slice to store the Shamir public polynomials
	ShamirPublicPolynomials := make([]*polynomial.Exponent, 0, len(r.VSSPolynomials))
	// Iterate through each VSS polynomial in r.VSSPolynomials.
	// Append the VSS polynomial to the ShamirPublicPolynomials slice.
	//Compute [F₁(X), …, Fₙ(X)]
	for _, VSSPolynomial := range r.VSSPolynomials {
		ShamirPublicPolynomials = append(ShamirPublicPolynomials, VSSPolynomial)
	}

	// ShamirPublicPolynomial = F(X) = ∑Fⱼ(X)
	ShamirPublicPolynomial, err := polynomial.Sum(ShamirPublicPolynomials)
	if err != nil {
		return r, err
	}

	// compute the new public key share Xⱼ = F(j) (+X'ⱼ if doing a refresh)
	PublicData := make(map[party.ID]*config.Public, len(r.PartyIDs()))
	// Iterate through each party ID in r.PartyIDs().
	for _, j := range r.PartyIDs() {
		// PublicECDSAShare 是一个点，表示F(j)*G
		// Evaluate the Shamir public polynomial at party j's scalar value (F(j)*G).
		PublicECDSAShare := ShamirPublicPolynomial.Evaluate(j.Scalar(r.Group()))
		if r.PreviousPublicSharesECDSA != nil {
			PublicECDSAShare = PublicECDSAShare.Add(r.PreviousPublicSharesECDSA[j])
		}
		// Create a new PublicData entry for party j.
		// Assign the ECDSA share, ElGamal public key, Paillier public key, and Pedersen commitment to the entry.
		PublicData[j] = &config.Public{
			ECDSA:    PublicECDSAShare,
			ElGamal:  r.ElGamalPublic[j],
			Paillier: r.PaillierPublic[j],
			Pedersen: pedersen.New(r.PaillierPublic[j].Modulus(), r.S[j], r.T[j]),
		}
	}

	UpdatedConfig := &config.Config{
		Group:     r.Group(),
		ID:        r.SelfID(),
		Threshold: r.Threshold(),
		ECDSA:     UpdatedSecretECDSA, //F(x_i)
		ElGamal:   r.ElGamalSecret,
		Paillier:  r.PaillierSecret,
		RID:       r.RID.Copy(),
		ChainKey:  r.ChainKey.Copy(),
		Public:    PublicData,
	}

	// write new ssid to hash, to bind the Schnorr proof to this new config
	// Write SSID, selfID to temporary hash
	h := r.Hash()
	_ = h.WriteAny(UpdatedConfig, r.SelfID())
	// Generate a Schnorr proof using the SchnorrRand object
	proof := r.SchnorrRand.Prove(h, PublicData[r.SelfID()].ECDSA, UpdatedSecretECDSA, nil)

	//if !proof.Verify(h, PublicData[r.SelfID()].ECDSA, r.SchnorrRand.Commitment(), nil) {
	//	log.Errorln("round4 failed to validate schnorr proof ")
	//}

	// Broadcast the Schnorr response to all parties.
	err = r.BroadcastMessage(out, &broadcast5{SchnorrResponse: proof})
	if err != nil {
		return r, err
	}
	// Update the hash state with the updated configuration (UpdatedConfig).
	r.UpdateHashState(UpdatedConfig)
	return &round5{
		round4:        r,
		UpdatedConfig: UpdatedConfig,
	}, nil
}

// RoundNumber implements round.Content.
func (message4) RoundNumber() round.Number { return 4 }

// MessageContent implements round.Round.
func (round4) MessageContent() round.Content { return &message4{} }

// RoundNumber implements round.Content.
func (broadcast4) RoundNumber() round.Number { return 4 }

// BroadcastContent implements round.BroadcastRound.
func (round4) BroadcastContent() round.BroadcastContent { return &broadcast4{} }

// Number implements round.Round.
func (round4) Number() round.Number { return 4 }