package test

import (
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/protocol"
)

// HandlerLoop blocks until the handler has finished. The result of the execution is given by Handler.Result().
func HandlerLoop(id party.ID, h protocol.Handler, network *Network) {
	for {
		select {

		// outgoing messages
		case msg, ok := <-h.Listen():
			if !ok {
				<-network.Done(id)
				// the channel was closed, indicating that the protocol is done executing.
				return
			}
			// launch a goroutine to execute the network.Send function
			go network.Send(msg)

		// incoming messages
		case msg := <-network.Next(id):
			h.Accept(msg)
		}
	}
}
