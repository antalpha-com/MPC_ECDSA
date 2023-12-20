// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presign3rounds

import (
	"MPC_ECDSA/internal/mta"
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/pkg/BigInt"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/party"
	zkaffg "MPC_ECDSA/pkg/zk/affg"
	zkdec "MPC_ECDSA/pkg/zk/dec"
	zkmulstar "MPC_ECDSA/pkg/zk/mulstar"
	"crypto/rand"
)

var _ round.Round = (*sign2)(nil)

type sign2 struct {
	*sign1
	// SigmaShares[j] = σⱼ 签名的分片
	SigmaShares map[party.ID]curve.Scalar
}

type broadcastSign2 struct {
	round.NormalBroadcastContent
	// Sigma = σᵢ
	Sigma curve.Scalar
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - save σⱼ.
func (r *sign2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcastSign2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.Sigma.IsZero() {
		return round.ErrNilFields
	}

	r.SigmaShares[msg.From] = body.Sigma
	return nil
}

// VerifyMessage implements round.Round.
func (sign2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (sign2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - verify (r,s)
// - if not, find culprit.
func (r *sign2) Finalize(out chan<- *round.Message) (round.Session, error) {
	//combines the given shares σⱼ and returns a pair (R,S), where S=∑ⱼσⱼ
	s := r.PreSignature.Signature(r.SigmaShares)

	//The  signature s is verified using the Verify method of the s object
	if s.Verify(r.PublicKey, r.Message) {
		//if the verification is successful (the signature is valid),
		//the ResultRound method is called with the s object to finalize the signing process.
		return r.ResultRound(s), nil
	}

	//If the signature verification fails, generate proofs to find culprits.
	// 构造proof，广播，返回abort2
	record := r.PreSignature.Record
	otherIDs := r.OtherPartyIDs()
	// re-prove D-hat zkaffg proof
	reChiProofs := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]
		//the multiplicative to additive proofs are generated using the mta.ProveAffG functions.
		_, _, _, ChiProof := mta.ProveAffG(r.Group(), r.HashForID(r.SelfID()),
			curve.MakeInt(record.SecretECDSA), record.ECDSA.Points[r.SelfID()], record.K[j],
			record.SecretPaillier, record.Paillier[j], record.Pedersen[j])

		return ChiProof
	})
	// 组成map
	reChiProofMap := make(map[party.ID]*zkaffg.Proofbuf)
	for idx, reChiProof := range reChiProofs {
		j := otherIDs[idx]
		reChiProofMap[j] = reChiProof.(*zkaffg.Proofbuf)
	}

	// mulstar proof
	verifierPaillier := record.Paillier[r.SelfID()]
	// ki Nat版本
	c := curve.MakeInt(r.PreSignature.KShare)
	C, _ := verifierPaillier.Enc(c)

	//Xi, XiNonce := r.Paillier[r.SelfID()].Enc(xi)
	x := curve.MakeInt(record.SecretECDSA)
	X := r.Group().NewScalar().SetNat(x.Mod1(r.Group().Order())).ActOnBase()

	// Hhat_i = enci(ki γᵢ)
	HHatShare := C.Clone().Mul(verifierPaillier, x)
	n := verifierPaillier.N()
	HiNonce := sample.UnitModN(rand.Reader, n)
	HHatShare.Randomize(verifierPaillier, HiNonce)
	//prove zkmulstar
	MulProofs := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]
		verifierPedersen := record.Pedersen[j]

		public := zkmulstar.Public{
			C: C,
			D: HHatShare,
			//D:        D,
			X:        X,
			Verifier: verifierPaillier,
			Aux:      verifierPedersen,
		}
		private := zkmulstar.Private{
			X:   x,
			Rho: HiNonce,
			//Rho: rho,
		}
		MulProof := zkmulstar.NewProofMal(r.Group(), r.HashForID(r.SelfID()), public, private)

		return MulProof
	})
	// 组成map
	MulProofMap := make(map[party.ID]*zkmulstar.Proofbuf)
	for idx, MulProof := range MulProofs {
		j := otherIDs[idx]
		MulProofMap[j] = MulProof.(*zkmulstar.Proofbuf)
	}

	// compute m*K_i + r*(HiHat_i + ∑(DHat_ij+FHat_ji) )
	sigmaExpect := HHatShare
	// Dij = r.DeltaCiphertext[j][r.SelfID()]
	for _, j := range r.OtherPartyIDs() {
		DHatij := record.ChiCiphertext[j][r.SelfID()]
		FHatji := record.FHatjiArray[j]
		// 这里根据ciphertext.go,应该是add而不是mul
		sigmaExpect = sigmaExpect.Add(record.Paillier[r.SelfID()], DHatij)
		sigmaExpect = sigmaExpect.Add(record.Paillier[r.SelfID()], FHatji)
	}
	Rx := curve.MakeInt(s.R.XScalar())
	sigmaExpect = sigmaExpect.Mul(record.Paillier[r.SelfID()], Rx)
	// sigmaExpect = Ki m  + sigmaExpect
	m := curve.FromHash(r.Group(), r.Message)
	mInt := curve.MakeInt(m)
	Ki := record.K[r.SelfID()]
	Kim := Ki.Mul(record.Paillier[r.SelfID()], mInt)
	sigmaExpect = sigmaExpect.Add(record.Paillier[r.SelfID()], Kim)

	// prove zkdec
	sigmaShareInt := curve.MakeInt(r.SigmaShares[r.SelfID()])
	sigmaProofs := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]
		sigmaProof := zkdec.NewProofMal(r.Group(), r.HashForID(r.SelfID()), zkdec.Public{
			C:      sigmaExpect,
			X:      r.SigmaShares[r.SelfID()],
			Prover: record.Paillier[r.SelfID()],
			Aux:    record.Pedersen[j],
		}, zkdec.Private{
			Y:   sigmaShareInt,
			Rho: new(BigInt.Nat).SetUint64(0x1122),
		})
		return sigmaProof
	})

	// 组成map
	sigmaDecProofMap := make(map[party.ID]*zkdec.Proofbuf)
	for idx, sigmaProof := range sigmaProofs {
		j := otherIDs[idx]
		sigmaDecProofMap[j] = sigmaProof.(*zkdec.Proofbuf)
	}
	// 消息广播出去
	broadcastMsg := broadcastAbort2{
		ReChiProofMap:    reChiProofMap,
		MulProofMap:      MulProofMap,
		SigmaDecProofMap: sigmaDecProofMap,
		HHatShare:        HHatShare,
		SigmaExpect:      sigmaExpect,
	}
	if err := r.BroadcastMessage(out, &broadcastMsg); err != nil {
		return r, err
	}
	return &abort2{
		sign2: r,
	}, nil

}

// MessageContent implements round.Round.
func (sign2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcastSign2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (r *sign2) BroadcastContent() round.BroadcastContent {
	return &broadcastSign2{
		Sigma: r.Group().NewScalar(),
	}
}

// Number implements round.Round.
func (sign2) Number() round.Number { return 2 }
