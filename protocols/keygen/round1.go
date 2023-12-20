package keygen

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/types"
	"MPC_ECDSA/pkg/BigInt"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/polynomial"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/party"
	zksch "MPC_ECDSA/pkg/zk/sch"
	"crypto/rand"
	"errors"
	log "github.com/sirupsen/logrus"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	//The auxiliary information before the first round, embedded in round1
	*round.Helper

	// PreviousSecretECDSA = sk'ᵢ
	// Contains the previous secret ECDSA key share which is being refreshed
	// Keygen:  sk'ᵢ = nil
	// Refresh: sk'ᵢ = sk'ᵢ
	PreviousSecretECDSA curve.Scalar

	// PreviousPublicSharesECDSA[j] = pk'ⱼ
	// Keygen:  pk'ⱼ = nil
	// Refresh: pk'ⱼ = pk'ⱼ
	PreviousPublicSharesECDSA map[party.ID]curve.Point

	// PreviousChainKey contains the chain key, if we're refreshing
	//
	// In that case, we will simply use the previous chain key at the very end.
	PreviousChainKey types.RID

	// VSSSecret = fᵢ(X)
	// Polynomial from which the new secret shares are computed.
	// Keygen:  fᵢ(0) = xⁱ
	// Refresh: fᵢ(0) = 0
	VSSSecret *polynomial.Polynomial
}

// VerifyMessage implements round.Round.
func (r *round1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
// - sample Paillier (pᵢ, qᵢ)
// - sample Pedersen Nᵢ, sᵢ, tᵢ
// - sample aᵢ  <- 𝔽
// - set Aᵢ = aᵢ⋅G
// - compute Fᵢ(X) = fᵢ(X)⋅G
// - sample ridᵢ <- {0,1}ᵏ
// - sample cᵢ <- {0,1}ᵏ
// - commit to message.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Generate Paillier public key and secret key
	PaillierSecret := paillier.NewSecretKey(nil)
	SelfPaillierPublic := PaillierSecret.PublicKey
	//Generate Pedersen public key and secret key ([s, t], λ)
	SelfPedersenPublic, PedersenSecret := PaillierSecret.GeneratePedersen()
	//Generate ElGamal public key and secret key (x, X), X=xG, G is base posint
	ElGamalSecret, ElGamalPublic := sample.ScalarPointPair(rand.Reader, r.Group())

	// save our own share already so we are consistent with what we receive from others
	SelfShare := r.VSSSecret.Evaluate(r.SelfID().Scalar(r.Group())) // f_i(x_i)

	// Compute Fᵢ(X) = fᵢ(X)•G
	SelfVSSPolynomial := polynomial.NewPolynomialExponent(r.VSSSecret)

	// Generate Schnorr randomness
	SchnorrRand := zksch.NewRandomness(rand.Reader, r.Group(), nil)

	// Sample RIDᵢ
	SelfRID, err := types.NewRID(rand.Reader)
	if err != nil {
		log.Errorln("failed to sample Rho")
		return r, errors.New("failed to sample Rho")
	}
	// Sample chainKey
	chainKey, err := types.NewRID(rand.Reader)
	if err != nil {
		log.Errorln("failed to sample c")
		return r, errors.New("failed to sample c")
	}

	// Make a hash commitment of data in message 2
	SelfCommitment, Decommitment, err := r.HashForID(r.SelfID()).Commit(
		SelfRID, chainKey, SelfVSSPolynomial, SchnorrRand.Commitment(), ElGamalPublic,
		SelfPedersenPublic.N(), SelfPedersenPublic.S(), SelfPedersenPublic.T())
	if err != nil {
		log.Errorln("failed to commit")
		return r, errors.New("failed to commit")
	}
	//Create a broadcast message of type broadcast2
	msg := &broadcast2{Commitment: SelfCommitment}
	//Broadcast the message to the recipients using the BroadcastMessage method of r.
	err = r.BroadcastMessage(out, msg)
	if err != nil {
		return r, err
	}

	nextRound := &round2{
		round1:         r,
		VSSPolynomials: map[party.ID]*polynomial.Exponent{r.SelfID(): SelfVSSPolynomial},
		Commitments:    map[party.ID]hash.Commitment{r.SelfID(): SelfCommitment},
		RIDs:           map[party.ID]types.RID{r.SelfID(): SelfRID},
		ChainKeys:      map[party.ID]types.RID{r.SelfID(): chainKey},
		ShareReceived:  map[party.ID]curve.Scalar{r.SelfID(): SelfShare},
		ElGamalPublic:  map[party.ID]curve.Point{r.SelfID(): ElGamalPublic},
		PaillierPublic: map[party.ID]*paillier.PublicKey{r.SelfID(): SelfPaillierPublic},
		NModulus:       map[party.ID]*BigInt.Nat{r.SelfID(): SelfPedersenPublic.N()},
		S:              map[party.ID]*BigInt.Nat{r.SelfID(): SelfPedersenPublic.S()},
		T:              map[party.ID]*BigInt.Nat{r.SelfID(): SelfPedersenPublic.T()},
		ElGamalSecret:  ElGamalSecret,
		PaillierSecret: PaillierSecret,
		PedersenSecret: PedersenSecret,
		SchnorrRand:    SchnorrRand,
		Decommitment:   Decommitment,
	}
	return nextRound, nil
}

// PreviousRound implements round.Round.
func (round1) PreviousRound() round.Round { return nil }

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }
