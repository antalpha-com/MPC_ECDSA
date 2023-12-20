package mta

import (
	"MPC_ECDSA/pkg/BigInt"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/pedersen"
	zkaffg "MPC_ECDSA/pkg/zk/affg"
	zkaffp "MPC_ECDSA/pkg/zk/affp"
	"crypto/rand"
)

// ProveAffG returns the necessary messages for the receiver of the
// h is a hash function initialized with the sender's ID.
// - senderSecretShare = aᵢ
// - senderSecretSharePoint = Aᵢ = aᵢ⋅G
// - receiverEncryptedShare = Encⱼ(bⱼ)
// The elements returned are :
// - Beta = β
// - D = (aⱼ ⊙ Bᵢ) ⊕ encᵢ(- β, s)
// - F = encⱼ(-β, r)
// - Proof = zkaffg proof of correct encryption.
func ProveAffG(group curve.Curve, h *hash.Hash,
	senderSecretShare *BigInt.Nat, senderSecretSharePoint curve.Point, receiverEncryptedShare *paillier.Ciphertext,
	sender *paillier.SecretKey, receiver *paillier.PublicKey, verifier *pedersen.Parameters) (Beta *BigInt.Nat, D, F *paillier.Ciphertext, Proof *zkaffg.Proofbuf) {
	D, F, S, R, BetaNeg := newMta(senderSecretShare, receiverEncryptedShare, sender, receiver)

	Proof = zkaffg.NewProofMal(group, h, zkaffg.Public{
		Kv:       receiverEncryptedShare,
		Dv:       D,
		Fp:       F,
		Xp:       senderSecretSharePoint,
		Prover:   sender.PublicKey,
		Verifier: receiver,
		Aux:      verifier,
	}, zkaffg.Private{
		X: senderSecretShare,
		Y: BetaNeg,
		S: S,
		R: R,
	})
	Beta = BetaNeg.Neg(1)
	return
}

// ProveAffP generates a proof for the a specified verifier.
// This function is specified as to make clear which parameters must be input to zkaffg.
// h is a hash function initialized with the sender's ID.
// - senderSecretShare = aᵢ
// - senderSecretSharePoint = Aᵢ = Encᵢ(aᵢ)
// - receiverEncryptedShare = Encⱼ(bⱼ)
// The elements returned are :
// - Beta = β
// - D = (aⱼ ⊙ Bᵢ) ⊕ encᵢ(-β, s)
// - F = encⱼ(-β, r)
// - Proof = zkaffp proof of correct encryption.
func ProveAffP(group curve.Curve, h *hash.Hash,
	senderSecretShare *BigInt.Nat, senderEncryptedShare *paillier.Ciphertext, senderEncryptedShareNonce *BigInt.Nat,
	receiverEncryptedShare *paillier.Ciphertext,
	sender *paillier.SecretKey, receiver *paillier.PublicKey, verifier *pedersen.Parameters) (Beta *BigInt.Nat, D, F *paillier.Ciphertext, Proof *zkaffp.Proofbuf) {
	D, F, S, R, BetaNeg := newMta(senderSecretShare, receiverEncryptedShare, sender, receiver)
	Proof = zkaffp.NewProofMal(group, h, zkaffp.Public{
		Kv:       receiverEncryptedShare,
		Dv:       D,
		Fp:       F,
		Xp:       senderEncryptedShare,
		Prover:   sender.PublicKey,
		Verifier: receiver,
		Aux:      verifier,
	}, zkaffp.Private{
		X:  senderSecretShare,
		Y:  BetaNeg,
		S:  S,
		Rx: senderEncryptedShareNonce,
		R:  R,
	})
	Beta = BetaNeg.Neg(1)

	return
}

func newMta(senderSecretShare *BigInt.Nat, receiverEncryptedShare *paillier.Ciphertext,
	sender *paillier.SecretKey, receiver *paillier.PublicKey) (D, F *paillier.Ciphertext, S, R *BigInt.Nat, BetaNeg *BigInt.Nat) {
	BetaNeg = sample.IntervalLPrime(rand.Reader)

	F, R = sender.Enc(BetaNeg) // F = encᵢ(-β, r)

	D, S = receiver.Enc(BetaNeg)
	tmp := receiverEncryptedShare.Clone().Mul(receiver, senderSecretShare) // tmp = aᵢ ⊙ Bⱼ
	D.Add(receiver, tmp)                                                   // D = encⱼ(-β;s) ⊕ (aᵢ ⊙ Bⱼ) = encⱼ(aᵢ•bⱼ-β)

	return
}
