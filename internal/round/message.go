package round

import (
	"MPC_ECDSA/pkg/party"
	"github.com/fxamacker/cbor/v2"
)

// Content represents the message, either broadcast or P2P returned by a round
// during finalization.
type Content interface {
	RoundNumber() Number
}

// BroadcastContent wraps a Content, but also indicates whether this content
// requires reliable broadcast.
type BroadcastContent interface {
	Content
	Reliable() bool
}

// These structs can be embedded in a broadcast message as a way of
// 1. implementing BroadcastContent
// 2. indicate to the handler whether the content should be reliably broadcast
// When non-unanimous halting is acceptable, we can use the echo broadcast.
type (
	ReliableBroadcastContent struct{}
	NormalBroadcastContent   struct{}
)

func (ReliableBroadcastContent) Reliable() bool { return true }
func (NormalBroadcastContent) Reliable() bool   { return false }

type Message struct {
	From, To  party.ID
	Broadcast bool
	Content   Content
}

// MarshalBinary function  serializes the message object into binary format.
func (m *Message) MarshalBinary() ([]byte, error) {
	return cbor.Marshal(m)
}

// UnmarshalBinary function  deserializes binary data into a message object.
func (m *Message) UnmarshalBinary(data []byte) error {
	deserialized := &Message{
		From:      m.From,
		To:        m.To,
		Broadcast: m.Broadcast,
		Content:   m.Content,
	}
	if err := cbor.Unmarshal(data, deserialized); err != nil {
		return nil
	}

	m.From = deserialized.From
	m.To = deserialized.To

	m.Broadcast = deserialized.Broadcast
	m.Content = deserialized.Content
	return nil
}
