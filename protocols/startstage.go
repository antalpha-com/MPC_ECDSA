// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package protocols

import (
	"MPC_ECDSA/communication"
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/pkg/ecdsa"
	"MPC_ECDSA/pkg/ecdsa3rounds"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pool"
	"MPC_ECDSA/pkg/protocol"
	"MPC_ECDSA/protocols/config"
	"MPC_ECDSA/protocols/keygen"
	"MPC_ECDSA/protocols/presign"
	"MPC_ECDSA/protocols/presign3rounds"
	"MPC_ECDSA/protocols/resharing"

	"MPC_ECDSA/protocols/sign"
)

// Config represents the stored state of a party who participated in a successful `Keygen` protocol.
// It contains secret key material and should be safely stored.
type Config = config.Config

// EmptyConfig creates an empty Config with a fixed group, ready for unmarshalling.
//
// This needs to be used for unmarshalling, otherwise the points on the curve can't
// be decoded.
func EmptyConfig(group curve.Curve) *Config {
	return &Config{
		Group: group,
	}
}

// Keygen generates a new shared ECDSA key over the curve defined by `group`. After a successful execution,
// all participants posses a unique share of this key, as well as auxiliary parameters required during signing.
//
// For better performance, a `pool.Pool` can be provided in order to parallelize certain steps of the protocol.
// Returns *cmp.Config if successful.
func Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool, useMnemonic bool) protocol.StartFunc {
	info := round.Info{
		ProtocolID:       "cmp/keygen-threshold",
		FinalRoundNumber: keygen.Rounds, // 5
		SelfID:           selfID,
		PartyIDs:         participants,
		Threshold:        threshold,
		Group:            group,
	}
	return keygen.Start(info, pl, nil, useMnemonic)
}

// Resharing allows for the modification of (t, n), where old participants can redistribute keys to new participants from a previously generated configuration
// The group's ECDSA public key remains the same, but any previous shares are rendered useless.
// Returns *cmp.Config if successful.
func Resharing(localConn *communication.LocalConn, pl *pool.Pool, Myconfig interface{}) protocol.StartFunc {
	var group = curve.Secp256k1{}
	Info := round.Info{
		ProtocolID:       "cmp/resharing-test",
		FinalRoundNumber: resharing.Rounds,
		SelfID:           localConn.LocalConfig.LocalID,
		PartyIDs:         localConn.LocalConfig.PartyIDs,
		Threshold:        localConn.LocalConfig.Threshold,
		Group:            group,
		KeyGenConfig:     Myconfig,
		NewPartyIDs:      localConn.LocalConfig.NewPartyIDs,
		OldPartyIDs:      localConn.LocalConfig.OldPartyIDs,
		NewThreshold:     localConn.LocalConfig.NewThreshold,
		IsNewCommittee:   localConn.LocalConfig.IsNewCommittee,
		IsOldCommittee:   localConn.LocalConfig.IsOldCommittee,
		OldOK:            make(map[party.ID]bool, len(localConn.LocalConfig.OldPartyIDs)),
		NewOK:            make(map[party.ID]bool, len(localConn.LocalConfig.NewPartyIDs)),
	}
	return resharing.Start(Info, pl)
	return nil
}
func Refresh(config *Config, pl *pool.Pool) protocol.StartFunc {
	info := round.Info{
		ProtocolID:       "cmp/keygen-threshold",
		FinalRoundNumber: keygen.Rounds, // 5
		SelfID:           config.ID,
		PartyIDs:         config.PartyIDs(),
		Threshold:        config.Threshold,
		Group:            config.Group,
	}
	return keygen.Start(info, pl, config, false)
}

// Sign generates an ECDSA signature for `messageHash` among the given `signers`.
// Returns *ecdsa.Signature if successful.
func Sign(config *Config, signers []party.ID, messageHash []byte, pl *pool.Pool) protocol.StartFunc {
	return sign.StartSign(config, signers, messageHash, pl)
}

// Presign generates a preprocessed signature that does not depend on the message being signed.
// When the message becomes available, the same participants can efficiently combine their shares
// to produce a full signature with the PresignOnline protocol.
// Note: the PreSignatures should be treated as secret key material.
// Returns *ecdsa.PreSignature if successful.
func Presign(config *Config, signers []party.ID, pl *pool.Pool) protocol.StartFunc {
	return presign.StartPresign(config, signers, nil, pl)
}

// SignAfterPresign efficiently generates an ECDSA signature for `messageHash` given a preprocessed `PreSignature`.
// Returns *ecdsa.Signature if successful.
func SignAfterPresign(config *Config, preSignature *ecdsa.PreSignature, messageHash []byte, pl *pool.Pool) protocol.StartFunc {
	return presign.StartPresignOnline(config, preSignature, messageHash, pl)
}

func Presign3rounds(config *Config, signers []party.ID, pl *pool.Pool) protocol.StartFunc {
	return presign3rounds.StartPresign(config, signers, nil, pl)
}

func SignAfterPresign3rounds(config *Config, signers []party.ID, preSignature *ecdsa3rounds.PreSignature3, messageHash []byte, pl *pool.Pool) protocol.StartFunc {
	return presign3rounds.StartPresignOnline(config, signers, preSignature, messageHash, pl)
}
