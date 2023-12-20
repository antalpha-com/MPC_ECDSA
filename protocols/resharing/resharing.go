// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/pkg/pool"
	"MPC_ECDSA/pkg/protocol"
	log "github.com/sirupsen/logrus"
)

const Rounds round.Number = 7

// Start returns a function that initializes and executes the resharing protocol.
func Start(info round.Info, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (_ round.Session, err error) {
		var helper *round.Helper
		helper, err = round.NewSession(info, sessionID, pl)
		if err != nil {
			log.Errorf("resharing: %v", err)
			return nil, err
		}
		return &round1{
			Helper: helper, //The Helper field stores the helper object that provides essential functionality and information for the protocol execution.
		}, nil
	}
}
