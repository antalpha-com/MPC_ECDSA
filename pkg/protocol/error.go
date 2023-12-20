package protocol

import (
	"fmt"

	"MPC_ECDSA/pkg/party"
)

// Error is a custom error for protocols which contains information about the responsible round in which it occurred,
// and the party responsible.
// 在基础的error类型做包装，加入敌手的ID数组
type Error struct {
	// Culprit is empty if the identity of the misbehaving party cannot be known.
	Culprits []party.ID
	// Err is the underlying error.
	Err error
}

// Error implement error.
func (e Error) Error() string {
	if e.Culprits == nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("culprits: %v: %s", e.Culprits, e.Err)
}

// Unwrap implement errors.Wrapper.
func (e Error) Unwrap() error {
	return e.Err
}
