package keygen

import (
	"errors"

	"MPC_ECDSA/internal/round"
	sch "MPC_ECDSA/pkg/zk/sch"
	"MPC_ECDSA/protocols/config"
)

var _ round.Round = (*round5)(nil)

type round5 struct {
	*round4
	UpdatedConfig *config.Config
}

type broadcast5 struct {
	round.NormalBroadcastContent
	// SchnorrResponse is the Schnorr proof of knowledge of the new secret share
	SchnorrResponse *sch.Response
}

// StoreBroadcastMessage implements round.BroadcastRound.
// StoreBroadcastMessage is used to store and validate a broadcast message received.
// - verify all Schnorr proof for the new ecdsa share.
func (r *round5) StoreBroadcastMessage(msg round.Message) error {
	// Retrieve the sender of the message.
	from := msg.From
	// Retrieve the body of the message and check if it is of type *broadcast5.
	body, ok := msg.Content.(*broadcast5)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	// Check if the Schnorr response in the message is valid
	if !body.SchnorrResponse.IsValid() {
		return round.ErrNilFields
	}
	// Verify the Schnorr proof in the Schnorr response
	if !body.SchnorrResponse.Verify(r.HashForID(from),
		r.UpdatedConfig.Public[from].ECDSA,
		r.SchnorrCommitments[from], nil) {
		return errors.New("failed to validate schnorr proof for received share")
	}
	return nil
}

// VerifyMessage implements round.Round.
func (round5) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round5) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *round5) Finalize(chan<- *round.Message) (round.Session, error) {
	return r.ResultRound(r.UpdatedConfig), nil
}

// MessageContent implements round.Round.
func (r *round5) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast5) RoundNumber() round.Number { return 5 }

// BroadcastContent implements round.BroadcastRound.
func (r *round5) BroadcastContent() round.BroadcastContent {
	return &broadcast5{
		SchnorrResponse: sch.EmptyResponse(r.Group()),
	}
}

// Number implements round.Round.
func (round5) Number() round.Number { return 5 }
