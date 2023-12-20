package test

import (
	"MPC_ECDSA/communication"
	"sync"

	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/protocol"
)

// Network simulates a point-to-point network between different parties using Go channels.
// The same network is used by all processes, and can be reused for different protocols.
// When used with test.Handler, no interaction from the user is required beyond creating the network.
type Network struct {
	parties          party.IDSlice
	listenChannels   map[party.ID]chan *protocol.Message
	done             chan struct{}
	closedListenChan chan *protocol.Message
	mtx              sync.Mutex
	localConn        communication.LocalConn
}

func NewNetwork(parties party.IDSlice, localConn *communication.LocalConn) *Network {
	closed := make(chan *protocol.Message)
	close(closed)
	c := &Network{
		parties:          parties,
		listenChannels:   make(map[party.ID]chan *protocol.Message, 2*len(parties)),
		closedListenChan: closed,
		localConn:        *localConn,
	}
	return c
}

// The init method initializes the network instance.
func (n *Network) init() {
	N := len(n.parties)
	// create a number of listen channels based on the number of parties
	for _, id := range n.parties {
		n.listenChannels[id] = make(chan *protocol.Message, N*N)
	}
	//initialize the done channel.
	n.done = make(chan struct{})
}

// Next method returns the listen channel for the specified party ID.
func (n *Network) Next(id party.ID) <-chan *protocol.Message {
	//lock the mutex
	n.mtx.Lock()
	defer n.mtx.Unlock()
	//initializes the network if needed
	if len(n.listenChannels) == 0 {
		n.init()
	}
	c, ok := n.listenChannels[id]
	//If the channel does not exist, it returns a closed listen channel.
	if !ok {
		return n.closedListenChan
	}
	return c
}

// Send method is used to send a message.
func (n *Network) Send(msg *protocol.Message) {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	//iterate over all listen channels,
	for id, c := range n.listenChannels {
		//check if the message is intended for a particular party ID
		if msg.IsFor(id) && c != nil {
			//send the message through the corresponding channel.
			n.listenChannels[id] <- msg
		}
	}
}

// Done method marks the completion of the listen channel for the specified party ID.
func (n *Network) Done(id party.ID) chan struct{} {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	// close the channel and remove it from the map.
	if _, ok := n.listenChannels[id]; ok {
		close(n.listenChannels[id])
		delete(n.listenChannels, id)
	}
	//If all listen channels are completed, it closes the done channel.
	if len(n.listenChannels) == 0 {
		close(n.done)
	}
	return n.done
}

// Quit method removes the specified party ID from the list of parties in the network.
func (n *Network) Quit(id party.ID) {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	n.parties = n.parties.Remove(id)
}
