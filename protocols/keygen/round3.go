package keygen

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/internal/types"
	"MPC_ECDSA/pkg/BigInt"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/polynomial"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pedersen"
	zkmod "MPC_ECDSA/pkg/zk/mod"
	zkprm "MPC_ECDSA/pkg/zk/prm"
	zksch "MPC_ECDSA/pkg/zk/sch"
	"errors"

	log "github.com/sirupsen/logrus"
)

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2
	// SchnorrCommitments[j] = Aⱼ
	// Commitment for proof of knowledge in the last round
	SchnorrCommitments map[party.ID]*zksch.Commitment // Aⱼ
}

type broadcast3 struct {
	round.NormalBroadcastContent
	// RID = RIDᵢ
	RID types.RID
	C   types.RID
	// VSSPolynomial = Fᵢ(X) VSSPolynomial
	VSSPolynomial *polynomial.Exponent
	// SchnorrCommitments = Aᵢ Schnorr commitment for the final confirmation
	SchnorrCommitments *zksch.Commitment
	ElGamalPublic      curve.Point
	// N Paillier and Pedersen N = p•q, p ≡ q ≡ 3 mod 4
	N *BigInt.Nat
	// S = r² mod N
	S *BigInt.Nat
	// T = Sˡ mod N
	T *BigInt.Nat
	// Decommitment = uᵢ decommitment bytes
	Decommitment hash.Decommitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - verify length of Schnorr commitments
// - verify degree of VSS polynomial Fⱼ "in-the-exponent"
//   - if keygen, verify Fⱼ(0) != ∞
//   - if refresh, verify Fⱼ(0) == ∞
//
// - validate Paillier
// - validate Pedersen
// - validate commitments.
// - store ridⱼ, Cⱼ, Nⱼ, Sⱼ, Tⱼ, Fⱼ(X), Aⱼ.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {

		return round.ErrInvalidContent
	}

	// check nil
	if body.N == nil || body.S == nil || body.T == nil || body.VSSPolynomial == nil {
		return round.ErrNilFields
	}
	// check RID length
	if err := body.RID.Validate(); err != nil {
		log.Errorln(err)
		return err
	}
	if err := body.C.Validate(); err != nil {
		log.Errorln(err)
		return err
	}
	// check decommitment
	if err := body.Decommitment.Validate(); err != nil {
		log.Errorln(err)
		return err
	}

	// Save all X, VSSCommitments
	VSSPolynomial := body.VSSPolynomial
	// check that the constant coefficient is 0
	// if refresh then the polynomial is constant
	if !(r.VSSSecret.Constant().IsZero() == VSSPolynomial.IsConstant) {
		log.Errorln("vss polynomial has incorrect constant")
		return errors.New("vss polynomial has incorrect constant")
	}
	// check deg(Fⱼ) = t
	if VSSPolynomial.Degree() != r.Threshold() {
		log.Errorln("vss polynomial has incorrect degree")
		return errors.New("vss polynomial has incorrect degree")
	}

	// Set Paillier
	if err := paillier.ValidateN(body.N); err != nil {
		log.Errorln(err)
		return err
	}

	// Verify Pedersen
	if err := pedersen.ValidateParameters(body.N, body.S, body.T); err != nil {
		log.Errorln(err)
		return err
	}
	// Verify decommit
	if !r.HashForID(from).Decommit(r.Commitments[from], body.Decommitment,
		body.RID, body.C, VSSPolynomial, body.SchnorrCommitments, body.ElGamalPublic, body.N, body.S, body.T) {
		log.Errorln("failed to decommit")
		return errors.New("failed to decommit")
	}
	r.RIDs[from] = body.RID
	r.ChainKeys[from] = body.C
	r.NModulus[from] = body.N
	r.S[from] = body.S
	r.T[from] = body.T
	r.PaillierPublic[from] = paillier.NewPublicKeyFromN(body.N)
	r.VSSPolynomials[from] = body.VSSPolynomial
	r.SchnorrCommitments[from] = body.SchnorrCommitments
	r.ElGamalPublic[from] = body.ElGamalPublic

	return nil
}

// VerifyMessage implements round.Round.
func (round3) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round3) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - set rid = ⊕ⱼ ridⱼ and update hash state
// - prove Nᵢ is Blum
// - prove Pedersen parameters
// - prove Schnorr for all coefficients of fᵢ(X)
//   - if refresh skip constant coefficient
//
// - send proofs and encryption of share for Pⱼ.
func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
	//Compute c = ⊕ⱼ cⱼ
	chainKey := r.PreviousChainKey
	if chainKey == nil {
		chainKey = types.EmptyRID()
		for _, j := range r.PartyIDs() {
			chainKey.XOR(r.ChainKeys[j])
		}
	}
	// Compute RID = ⊕ⱼ RIDⱼ
	rid := types.EmptyRID()
	for _, j := range r.PartyIDs() {
		rid.XOR(r.RIDs[j])
	}

	// temporary hash which does not modify the state
	h := r.Hash()
	_ = h.WriteAny(rid, r.SelfID())

	// Prove N is a blum prime with zkmod n = pq
	mod := zkmod.NewProofMal(h.Clone(), zkmod.Private{
		P:   r.PaillierSecret.P(),
		Q:   r.PaillierSecret.Q(),
		Phi: r.PaillierSecret.Phi(),
	}, zkmod.Public{N: r.NModulus[r.SelfID()]}, r.Pool)

	// Prove s, t are correct as aux parameters with zkprm s = t^lambda (mod N).
	prm := zkprm.NewProofMal(zkprm.Private{
		Lambda: r.PedersenSecret,
		Phi:    r.PaillierSecret.Phi(),
		P:      r.PaillierSecret.P(),
		Q:      r.PaillierSecret.Q(),
	}, h.Clone(), zkprm.Public{N: r.NModulus[r.SelfID()], S: r.S[r.SelfID()], T: r.T[r.SelfID()]}, r.Pool)

	if err := r.BroadcastMessage(out, &broadcast4{
		Mod: mod,
		Prm: prm,
	}); err != nil {
		return r, err
	}

	// create messages with encrypted shares
	for _, j := range r.OtherPartyIDs() {
		// compute fᵢ(j)
		share := r.VSSSecret.Evaluate(j.Scalar(r.Group()))

		// Encrypt share
		C, _ := r.PaillierPublic[j].Enc(curve.MakeInt(share))

		err := r.SendMessage(out, &message4{
			Share: C,
		}, j)
		if err != nil {
			return r, err
		}
	}

	// Write rid to the hash state
	r.UpdateHashState(rid)
	return &round4{
		round3:   r,
		RID:      rid,
		ChainKey: chainKey,
	}, nil
}

// MessageContent implements round.Round.
func (round3) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &broadcast3{
		VSSPolynomial:      polynomial.EmptyExponent(r.Group()),
		SchnorrCommitments: zksch.EmptyCommitment(r.Group()),
		ElGamalPublic:      r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
