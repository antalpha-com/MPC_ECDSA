package presign

import (
	"errors"

	"MPC_ECDSA/internal/round"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/party"
	zknth "MPC_ECDSA/pkg/zk/nth"

	"MPC_ECDSA/pkg/BigInt"
)

var _ round.Round = (*abort1)(nil)

type abort1 struct {
	*presign6
	GammaShares map[party.ID]*BigInt.Nat
	KShares     map[party.ID]*BigInt.Nat
	// DeltaAlphas[j][k] = αⱼₖ
	DeltaAlphas map[party.ID]map[party.ID]*BigInt.Nat
}

// The broadcastAbort1 struct represents the broadcast message content for the abort1 round.
type broadcastAbort1 struct {
	round.NormalBroadcastContent
	// GammaShare = γᵢ
	GammaShare  *BigInt.Nat
	KProof      *abortNth
	DeltaProofs map[party.ID]*abortNth
}

// StoreBroadcastMessage function is a method of the abort1 struct.
// It is used to store and validate the broadcast message received during the abort1 round.
func (r *abort1) StoreBroadcastMessage(msg round.Message) error {
	//Extract the sender of the message
	from := msg.From
	//Check that the content of the message is of type broadcastAbort1 and assign it to the body variable.

	body, ok := msg.Content.(*broadcastAbort1)
	//If the content is not of the expected type or is nil, return an ErrInvalidContent error.
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	//Create a map alphas to store the delta alphas (plaintext values) for each party
	alphas := make(map[party.ID]*BigInt.Nat, len(body.DeltaProofs))
	for id, deltaProof := range body.DeltaProofs {
		alphas[id] = deltaProof.Plaintext
	}
	r.DeltaAlphas[from] = alphas
	r.GammaShares[from] = body.GammaShare
	r.KShares[from] = body.KProof.Plaintext
	//Retrieve the public key
	public := r.Paillier[from]
	//Verify the validity of the k share
	if !body.KProof.Verify(r.HashForID(from), public, r.K[from]) {
		return errors.New("failed to verify validity of k")
	}

	BigGammaShareActual := r.Group().NewScalar().SetNat(body.GammaShare.Mod1(r.Group().Order())).ActOnBase()
	if !r.BigGammaShare[from].Equal(BigGammaShareActual) {
		return errors.New("different BigGammaShare")
	}
	//verify the validity of each delta Nth proof.
	for id, deltaProof := range body.DeltaProofs {
		if !deltaProof.Verify(r.HashForID(from), public, r.DeltaCiphertext[from][id]) {
			return errors.New("failed to validate Delta MtA Nth proof")
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
	var (
		culprits   []party.ID
		delta, tmp BigInt.Nat
	)
	//iterate over the other party IDs in the round
	for _, j := range r.OtherPartyIDs() {
		//calculate the value of delta as the product of r.KShares[j] and r.GammaShares[j]
		//delta=r.KShares[j] *r.GammaShares[j]
		delta.Mul(r.KShares[j], r.GammaShares[j], -1)
		//Iterate over all party IDs l
		for _, l := range r.PartyIDs() {
			if l == j {
				continue
			}
			delta.Add(&delta, r.DeltaAlphas[j][l], -1)
			tmp.Mul(r.KShares[l], r.GammaShares[j], -1)
			delta.Add(&delta, &tmp, -1)
			tmp.SetNat(r.DeltaAlphas[l][j]).Neg(1)
			delta.Add(&delta, &tmp, -1)
		}
		deltaScalar := r.Group().NewScalar().SetNat(delta.Mod1(r.Group().Order()))
		//Check if deltaScalar is equal to r.DeltaShares[j].
		if !deltaScalar.Equal(r.DeltaShares[j]) {
			//If they are not equal, append j to the culprits slice.
			culprits = append(culprits, j)
		}
	}
	return r.AbortRound(errors.New("abort1: detected culprit"), culprits...), nil
}

// MessageContent implements round.Round.
func (abort1) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcastAbort1) RoundNumber() round.Number { return 7 }

// BroadcastContent implements round.BroadcastRound.
func (r *abort1) BroadcastContent() round.BroadcastContent { return &broadcastAbort1{} }

// Number implements round.Round.
func (abort1) Number() round.Number { return 7 }

type abortNth struct {
	Plaintext *BigInt.Nat
	Nonce     *BigInt.Nat
	Proof     *zknth.Proofbuf
}

// proveNth function is to provide a proof mechanism based on the Paillier encryption scheme(proof R = r = ρᴺ (mod N²))
// The function takes a hash object (hash), a Paillier secret key (paillierSecret), and a Paillier ciphertext (c) as input.
func proveNth(hash *hash.Hash, paillierSecret *paillier.SecretKey, c *paillier.Ciphertext) *abortNth {
	NSquared := paillierSecret.ModulusSquared() // N^2
	N := paillierSecret.Modulus()               //N
	//Decrypts the Paillier ciphertext c to obtain the plaintext (deltaShareAlpha) and the nonce (deltaNonce)
	deltaShareAlpha, deltaNonce, _ := paillierSecret.DecWithRandomness(c)

	deltaNonceHidden := new(BigInt.Nat).Exp(deltaNonce, N.Nat(), NSquared)
	//Constructs a proof using the zknth package,
	//which proves the relation R = r = ρᴺ (mod N²), where R is deltaNonceHidden and r is deltaNonce.
	proof := zknth.NewProofMal(hash, zknth.Public{
		N: paillierSecret.PublicKey,
		R: deltaNonceHidden,
	}, zknth.Private{Rho: deltaNonce})
	return &abortNth{
		Plaintext: deltaShareAlpha,
		Nonce:     deltaNonceHidden,
		Proof:     proof,
	}
}

// Verify verifies the correctness of the abortNth proof
func (msg *abortNth) Verify(hash *hash.Hash, paillierPublic *paillier.PublicKey, c *paillier.Ciphertext) bool {
	//Checks if the abortNth message (msg) is not nil,
	//the nonce (msg.Nonce) is a valid modulus N,
	//and the plaintext (msg.Plaintext) is not nil.
	if msg == nil || !BigInt.IsValidNatModN(paillierPublic.N(), msg.Nonce) || msg.Plaintext == nil {
		return false
	}
	one := new(BigInt.Nat).SetUint64(1)
	cExpected := c.Nat()
	//Computes the actual ciphertext
	cActual := paillierPublic.EncWithNonce(msg.Plaintext, one).Nat()
	cActual.ModMul(cActual, msg.Nonce, paillierPublic.ModulusSquared())
	//Compare cExpected and cActual to check if they are equal.
	if cExpected.Eq(cActual) != 1 {
		return false
	}
	if !msg.Proof.VerifyMal(hash, zknth.Public{
		N: paillierPublic,
		R: msg.Nonce,
	}) {
		return false
	}
	return true
}
