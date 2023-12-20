// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.
package ecdsa3rounds

import (
	"MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/pedersen"
	"errors"
	"fmt"

	"MPC_ECDSA/internal/types"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
)

type PresignRecord struct {
	SecretECDSA    curve.Scalar
	ECDSA          *party.PointMap
	K              map[party.ID]*gmp_paillier.Ciphertext
	SecretPaillier *gmp_paillier.SecretKey
	Paillier       map[party.ID]*gmp_paillier.PublicKey
	Pedersen       map[party.ID]*pedersen.Parameters
	ChiCiphertext  map[party.ID]map[party.ID]*gmp_paillier.Ciphertext
	FHatjiArray    map[party.ID]*gmp_paillier.Ciphertext
	ChiFs          map[party.ID]*gmp_paillier.Ciphertext
}

type PreSignature3 struct {
	// ID is a random identifier for this specific presignature.
	ID types.RID
	// R = δ⁻¹⋅Γ = δ⁻¹⋅(∑ⱼ Γⱼ) = (∑ⱼδ⁻¹γⱼ)⋅G = k⁻¹⋅G
	R curve.Point
	// KShare = kᵢ
	KShare curve.Scalar
	// ChiShare = χᵢ
	ChiShare curve.Scalar
	// data prepared for find culprits
	Record *PresignRecord
}

// EmptyPresignRecord returns a PresignRecord with a given group, ready for unmarshalling.
func EmptyPresignRecord(group curve.Curve) *PresignRecord {
	return &PresignRecord{
		SecretECDSA:   group.NewScalar(),
		ECDSA:         party.EmptyPointMap(group),
		K:             make(map[party.ID]*gmp_paillier.Ciphertext),
		Paillier:      make(map[party.ID]*gmp_paillier.PublicKey),
		Pedersen:      make(map[party.ID]*pedersen.Parameters),
		ChiCiphertext: make(map[party.ID]map[party.ID]*gmp_paillier.Ciphertext),
		FHatjiArray:   make(map[party.ID]*gmp_paillier.Ciphertext),
		ChiFs:         make(map[party.ID]*gmp_paillier.Ciphertext),
	}
}

// Group returns the elliptic curve group associated with this PreSignature3.
func (sig *PreSignature3) Group() curve.Curve {
	return sig.R.Curve()
}

// EmptyPreSignature returns a PreSignature3 with a given group, ready for unmarshalling.
func EmptyPreSignature(group curve.Curve) *PreSignature3 {
	return &PreSignature3{
		R:        group.NewPoint(),
		KShare:   group.NewScalar(),
		ChiShare: group.NewScalar(),
		Record:   EmptyPresignRecord(group),
	}
}

// SignatureShare represents an individual additive share of the signature's "s" component.
type SignatureShare = curve.Scalar

// SignatureShare returns this party's share σᵢ = kᵢm+rχᵢ, where s = ∑ⱼσⱼ.
func (sig *PreSignature3) SignatureShare(hash []byte) curve.Scalar {
	m := curve.FromHash(sig.Group(), hash)
	r := sig.R.XScalar() // 获取R的横坐标的标量值
	mk := m.Mul(sig.KShare)
	rx := r.Mul(sig.ChiShare)
	sigma := mk.Add(rx)
	return sigma
}

// Signature combines the given shares σⱼ and returns a pair (R,S), where S=∑ⱼσⱼ.
func (sig *PreSignature3) Signature(shares map[party.ID]SignatureShare) *Signature {
	s := sig.Group().NewScalar()
	for _, sigma := range shares {
		s.Add(sigma)
	}
	return &Signature{
		R: sig.R,
		S: s,
	}
}

//// 这里实现的是output失败然后抓敌手的调用
//// 我觉得3轮的可能不能在这里验证，复杂，而且需要通信广播proof来验证，放在新的一轮怎样
//// VerifySignatureShares should be called if the signature returned by PreSignature3.Signature is not valid.
//// It returns the list of parties whose shares are invalid.
//func (sig *PreSignature3) VerifySignatureShares(shares map[party.ID]SignatureShare, hash []byte) (culprits []party.ID) {
//	r := sig.R.XScalar()
//	m := curve.FromHash(sig.Group(), hash)
//	for j, share := range shares {
//		Rj, Sj := sig.RBar.Points[j], sig.S.Points[j]
//		if Rj == nil || Sj == nil {
//			culprits = append(culprits, j)
//			continue
//		}
//		lhs := share.Act(sig.R)
//		rhs := m.Act(Rj).Add(r.Act(Sj))
//		if !lhs.Equal(rhs) {
//			culprits = append(culprits, j)
//		}
//	}
//	return
//}

func (sig *PreSignature3) Validate() error {

	if sig.R.IsIdentity() {
		return errors.New("presignature: R is identity")
	}
	if err := sig.ID.Validate(); err != nil {
		return fmt.Errorf("presignature: %w", err)
	}
	if sig.ChiShare.IsZero() || sig.KShare.IsZero() {
		return errors.New("ChiShare or KShare is invalid")
	}
	return nil
}
