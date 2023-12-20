// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.
package protocol

import (
	"MPC_ECDSA/communication"
	"bytes"
	"errors"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/pkg/hash"
	"MPC_ECDSA/pkg/party"

	"github.com/fxamacker/cbor/v2"
)

// StartFunc is function that creates the first round of a protocol.
// It returns the first round initialized with the session information.
// If the creation fails (likely due to misconfiguration), and error is returned.
//
// An optional sessionID can be provided, which should unique among all protocol executions.
type StartFunc func(sessionID []byte) (round.Session, error)

// Handler represents some kind of handler for a protocol.
type Handler interface {
	// Result should return the result of running the protocol, or an error
	Result() (interface{}, error)
	// Listen returns a channel which will receive new messages
	Listen() <-chan *Message
	// Stop should abort the protocol execution.
	Stop()
	// CanAccept checks whether or not a message can be accepted at the current point in the protocol.
	CanAccept(msg *Message) bool
	// Accept advances the protocol execution after receiving a message.
	Accept(msg *Message)
}

// MultiHandler represents an execution of a given protocol.
// It provides a simple interface for the user to receive/deliver protocol messages.
type MultiHandler struct {
	currentRound    round.Session
	rounds          map[round.Number]round.Session
	err             *Error
	result          interface{}
	messages        map[round.Number]map[party.ID]*Message
	broadcast       map[round.Number]map[party.ID]*Message
	broadcastHashes map[round.Number][]byte
	out             chan *Message
	mtx             sync.Mutex
	localConn       communication.LocalConn //通信
}

// NewMultiHandler creates a handler for a protocol based on the provided StartFunc.
// It takes a StartFunc, sessionID, and localConn parameters and returns a pointer to a MultiHandler and an error.
func NewMultiHandler(create StartFunc, sessionID []byte, localConn communication.LocalConn) (*MultiHandler, error) {
	//Use the create function with the sessionID to create the initial round of the protocol.
	r, err := create(sessionID)
	if err != nil {
		return nil, fmt.Errorf("protocol: failed to create round: %w", err)
	}
	// Creates a MultiHandler object h
	h := &MultiHandler{
		currentRound: r,
		// A map that tracks all rounds of the protocol, with the initial round added.
		rounds: map[round.Number]round.Session{r.Number(): r},
		//A queue to store received messages, initialized with the IDs of other parties and the final round number.
		messages: newQueue(r.OtherPartyIDs(), r.FinalRoundNumber()),
		//A queue to store broadcast messages, initialized with the IDs of other parties and the final round number.
		broadcast: newQueue(r.OtherPartyIDs(), r.FinalRoundNumber()),
		//A map to store the hashes of broadcast messages, initially empty.
		broadcastHashes: map[round.Number][]byte{},
		//A channel of Message type with a buffer size of 2 times the total number of parties.
		out:       make(chan *Message, 2*r.N()),
		localConn: localConn,
	}
	//call the finalize  method to execute the current round of the protocol
	h.finalize()
	return h, nil
}

// NewMultiHandlerReshare creates a handler for a protocol based on the provided StartFunc.
// It takes a StartFunc, sessionID, and localConn parameters and returns a pointer to a MultiHandler and an error.
func NewMultiHandlerReshare(create StartFunc, sessionID []byte, localConn communication.LocalConn) (*MultiHandler, error) {
	//Use the create function with the sessionID to create the initial round of the protocol.
	r, err := create(sessionID)
	if err != nil {
		return nil, fmt.Errorf("protocol: failed to create round: %w", err)
	}
	// Creates a MultiHandler object h
	h := &MultiHandler{
		currentRound: r,
		// A map that tracks all rounds of the protocol, with the initial round added.
		rounds: map[round.Number]round.Session{r.Number(): r},
		//A queue to store received messages, initialized with the IDs of other parties and the final round number.
		messages: newQueue(r.OtherPartyIDs(), r.FinalRoundNumber()),
		//A queue to store broadcast messages, initialized with the IDs of other parties and the final round number.
		broadcast: newQueue(r.OtherPartyIDs(), r.FinalRoundNumber()),
		//A map to store the hashes of broadcast messages, initially empty.
		broadcastHashes: map[round.Number][]byte{},
		//A channel of Message type with a buffer size of 2 times the total number of parties.
		out:       make(chan *Message, 2*r.N()),
		localConn: localConn,
	}
	//call the finalizeReshare  method to execute the current round of the protocol
	h.finalizeReshare()

	return h, nil
}

// Result returns the protocol result if the protocol completed successfully.
func (h *MultiHandler) Result() (interface{}, error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	if h.result != nil {
		return h.result, nil
	}
	if h.err != nil {
		return nil, *h.err
	}
	return nil, errors.New("protocol: not finished")
}

// Listen returns a channel with outgoing messages that must be sent to other parties.
// The message received should be _reliably_ broadcast if msg.Broadcast is true.
// The channel is closed when either an error occurs or the protocol detects an error.
func (h *MultiHandler) Listen() <-chan *Message {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.out
}

// CanAccept returns true if the message is designated for this protocol execution.
func (h *MultiHandler) CanAccept(msg *Message) bool {
	r := h.currentRound
	if msg == nil {
		return false
	}
	// are we the intended recipient 消息是不是当前这一轮的
	if !msg.IsFor(r.SelfID()) {
		return false
	}
	// is the protocol ID correct 是不是当前这个协议的
	if msg.Protocol != r.ProtocolID() {
		return false
	}
	// check for same SSID——协议执行的唯一标识
	if !bytes.Equal(msg.SSID, r.SSID()) {
		return false
	}
	// do we know the sender
	if !r.PartyIDs().Contains(msg.From) {
		return false
	}

	// data is cannot be nil
	if msg.Data == nil {
		return false
	}

	// check if message for unexpected round
	if msg.RoundNumber > r.FinalRoundNumber() {
		return false
	}

	if msg.RoundNumber < r.Number() && msg.RoundNumber > 0 {
		return false
	}

	return true
}

// Accept tries to process the given message. If an abort occurs, the channel returned by Listen() is closed,
// and an error is returned by Result().
//
// This function may be called concurrently from different threads but may block until all previous calls have finished.
func (h *MultiHandler) Accept(msg *Message) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	// exit early if the message is bad, or if we are already done
	if !h.CanAccept(msg) || h.err != nil || h.result != nil || h.duplicate(msg) {
		return
	}

	// a msg with roundNumber 0 is considered an abort from another party
	if msg.RoundNumber == 0 {
		h.abort(fmt.Errorf("aborted by other party with error: \"%s\"", msg.Data), msg.From)
		return
	}

	h.store(msg)
	//if h.currentRound.Number() != msg.RoundNumber {
	//	return
	//}

	if msg.Broadcast {
		if err := h.verifyBroadcastMessage(msg); err != nil {
			h.abort(err, msg.From)
			return
		}
	} else {
		if err := h.verifyMessage(msg); err != nil {
			h.abort(err, msg.From)
			return
		}
	}
}

// 调用round的StoreBroadcastMessage保存进round的信息
func (h *MultiHandler) verifyBroadcastMessage(msg *Message) error {
	r, ok := h.rounds[msg.RoundNumber]
	if !ok {
		return nil
	}

	// try to convert the raw message into a round.Message
	// 此时的data还是byte[]，从字节流变为 round.Message 类型
	roundMsg, err := getRoundMessage(msg, r)
	if err != nil {
		return err
	}

	// store the broadcast message for this round
	if err = r.(round.BroadcastRound).StoreBroadcastMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	// if the round only expected a broadcast message, we can safely return
	if !expectsNormalMessage(r) {
		return nil
	}

	// otherwise, we can try to handle the p2p message that may be stored.
	msg = h.messages[msg.RoundNumber][msg.From]
	if msg == nil {
		return nil
	}

	return h.verifyMessage(msg)
}

// verifyMessage tries to handle a normal (non reliably broadcast) message for this current round.
func (h *MultiHandler) verifyMessage(msg *Message) error {
	// we simply return if we haven't reached the right round.
	r, ok := h.rounds[msg.RoundNumber]
	if !ok {
		return nil
	}
	// exit if we don't yet have the broadcast message
	if _, ok = r.(round.BroadcastRound); ok {
		q := h.broadcast[msg.RoundNumber]
		if q == nil || q[msg.From] == nil {
			return nil
		}
	}

	roundMsg, err := getRoundMessage(msg, r)
	if err != nil {
		return err
	}

	// verify message for round
	if err = r.VerifyMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	if err = r.StoreMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	return nil
}

// The finalize method is responsible for executing the current round of the protocol
// and switching the execution state based on the result
func (h *MultiHandler) finalize() {
	log.Infoln("begin finalize")
	//Verify if all messages have been received
	if !h.receivedAll() {
		return
	}
	// Check broadcast message hashes by calling the receivedAll method
	if !h.checkBroadcastHash() {
		h.abort(errors.New("broadcast verification failed"))
		return
	}
	// Create a channel for communication in the current round and collect messages to be sent by the local participant
	out := make(chan *round.Message, h.currentRound.N()+1)
	// Call the Finalize method of the current round to calculate and send messages, and obtain the next round
	r, err := h.currentRound.Finalize(out)
	//Close the out channel to indicate that no more messages will be sent.
	close(out)
	//If there is an error during the finalization process or the next round is not obtained
	if err != nil || r == nil {
		//abort the protocol execution by calling the abort method with the error and the self ID of the current round.
		h.abort(err, h.currentRound.SelfID())
		return
	}
	// Declare and initialize auxiliary variables to calculate the number of messages to be received
	numMsg := 0
	numBroadcast := 0
	numP2p := 0

	// Send messages to other participants
	// Iterate over messages in the 'out' channel, serialize them, and handle them based on their nature (broadcast or p2p)
	// Calculate the number of messages to be received in the process
	for roundMsg := range out {
		//serialize the roundMsg.Content
		data, err := cbor.Marshal(roundMsg.Content)
		if err != nil {
			panic(fmt.Errorf("failed to marshal round message: %w", err))
		}
		//creates a Message struct
		msg := &Message{
			SSID:                  r.SSID(),
			From:                  r.SelfID(),
			To:                    roundMsg.To,
			Protocol:              r.ProtocolID(),
			RoundNumber:           roundMsg.Content.RoundNumber(),
			Data:                  data,
			Broadcast:             roundMsg.Broadcast, //bool
			BroadcastVerification: h.broadcastHashes[r.Number()-1],
		}
		//serialize the msg
		byteMsg, err := cbor.Marshal(msg)
		if err != nil {
			panic(fmt.Errorf("failed to marshal handler message: %w", err))
		}

		//If the message is a broadcast message
		if msg.Broadcast {
			// Increment the numBroadcast counter,
			numBroadcast += 1
			log.Infof("broadcast message %+v", msg)
			//broadcasts 'byteMsg' using the localConn.BroadcastSend method
			err := h.localConn.BroadcastSend(byteMsg)
			if err != nil {
				log.Errorf("fail broadcast message")
			}
			// Store the broadcast message in the local handler
			h.store(msg)
		} else {
			//If the message is a point-to-point message increment the numP2p counter
			numP2p += 1
			log.Infof("p2p send message to %v", roundMsg.To)
			//send message(byteMsg) to the recipient(roundMsg.To) using the localConn.P2pSend method.
			err := h.localConn.P2pSend(roundMsg.To, byteMsg)
			if err != nil {
				log.Errorf("fail p2p send to  %v", roundMsg.To)
			}
		}
	}
	log.Infof("switch to new round %v", r.Number())
	roundNumber := r.Number()
	//check if the new round already exists in the h.rounds map
	//If the round exists, it returns without further processing.
	if _, ok := h.rounds[roundNumber]; ok {
		return
	}
	h.rounds[roundNumber] = r
	h.currentRound = r

	//It creates a channel named done to mark the completion of message reception.
	done := make(chan bool)
	//calculate the number of otherParties
	otherPartyNum := h.localConn.LocalConfig.TotalPartyCount - 1
	//calculate the total number of messages to be received
	//based on the number of broadcast and point-to-point messages.
	numMsg = numBroadcast*otherPartyNum + numP2p
	//calculate the number of rounds the local participant needs to receive messages,
	//assuming each round receives otherPartyNum messages.
	numReceiveRound := numMsg / otherPartyNum

	//use a goroutine to asynchronously handle message reception.
	go func(numReceiveRound int) {
		log.Infof("numMsg is %v\n", numReceiveRound)
		var msgMap map[party.ID][]byte
		for i := 0; i < numReceiveRound; i++ {
			// call the BroadcastReceive method to receive messages from other participants
			msgMap, err = h.localConn.BroadcastReceive()
			if err != nil {
				log.Errorln("fail BroadcastReceive")
				return
			}
			wg := sync.WaitGroup{}
			wg.Add(len(msgMap))
			//iterate over the received messages
			for id, msgByte := range msgMap {
				//process each message in parallel using goroutines.
				go func(id party.ID, msgByte []byte) {
					defer wg.Done()
					tmpMsg := &Message{}
					//unmarshal them into Message structs(tmpMsg)
					err = cbor.Unmarshal(msgByte, tmpMsg)
					if err != nil {
						log.Errorf("fail unmarshal %v", err)
					}
					log.Infof("received from party %v, message is %+v", id, tmpMsg)
					//call the Accept method of the handler to handle the message.
					h.Accept(tmpMsg)
				}(id, msgByte)
			}
			wg.Wait()

		}
		//After processing all received messages, it signals the completion of message reception by sending a value to the done channel.
		done <- true
	}(numReceiveRound)

	//wait for the completion signal from the done channel using a select statement
	select {
	case <-done:
		// either we get the current round, the next one, or one of the two final ones
		switch R := r.(type) {
		//If it is an Abort round, indicating an error occurred,
		//it calls the abort method with the error and culprits (if any) and returns.
		case *round.Abort:
			h.abort(R.Err, R.Culprits...)
			return
			//it is an Output round, indicating the protocol has produced a result,
			//it assigns the result to the h.result field
			//and calls the abort method without an error to terminate the protocol execution.
		case *round.Output:
			h.result = R.Result
			h.abort(nil)
			return
		default:
		}
		// Recursively call finalize to enter the next round
		h.finalize()
	}
}

// For new party,set a map, the key is roundNumber,
// the value indicates whether the message comes from the new participant or the old participant,
var numReceiveRoundMapNewParty = map[int]int{
	1: 0,  // round1 does not receive messages
	2: -1, // round2 receives messages from old party
	3: 1,  // round3 receives messages from new party
	4: -1, // round4 receives messages from old party
	5: 1,  // round5 receives messages from new party
	6: 1,  // round6 receives messages from new party
	7: 1,  // round7 receives messages from new party
}

// The finalizeReshare method is responsible for executing the current round of the protocol
// and switching the execution state based on the result
func (h *MultiHandler) finalizeReshare() {
	log.Infoln("begin finalizeReshare")
	// Create a channel for communication in the current round and collect messages to be sent by the local participant
	out := make(chan *round.Message, h.currentRound.N()+1)
	// Call the Finalize method of the current round to calculate and send messages, and obtain the next round
	r, err := h.currentRound.Finalize(out)
	//Close the out channel to indicate that no more messages will be sent.
	close(out)
	//If there is an error during the finalization process or the next round is not obtained
	if err != nil || r == nil {
		//abort the protocol execution by calling the abort method with the error and the self ID of the current round.
		//h.abort(err, h.currentRound.SelfID())
		log.Errorln("fail to finalize Reshare")
		return
	}
	// Send messages to other participants
	// Iterate over messages in the 'out' channel, serialize them, and handle them
	for roundMsg := range out {
		//serialize the roundMsg.Content
		data, err := cbor.Marshal(roundMsg.Content)
		if err != nil {
			panic(fmt.Errorf("failed to marshal round message: %w", err))
		}
		//creates a Message struct
		msg := &Message{
			SSID:        r.SSID(),
			From:        r.SelfID(),
			To:          roundMsg.To,
			Protocol:    r.ProtocolID(),
			RoundNumber: roundMsg.Content.RoundNumber(),
			Data:        data,
		}
		//serialize the msg
		byteMsg, err := cbor.Marshal(msg)
		if err != nil {
			panic(fmt.Errorf("failed to marshal handler message: %w", err))
		}
		//send message(byteMsg) to the recipient(roundMsg.To) using the localConn.P2pSend method.
		err = h.localConn.P2pSend(roundMsg.To, byteMsg)
		if err != nil {
			log.Errorf("fail p2p send to  %v", roundMsg.To)
		}
	}
	log.Infof("switch to new round %v", r.Number())
	roundNumber := r.Number()
	//check if the new round already exists in the h.rounds map
	//If the round exists, it returns without further processing.
	if _, ok := h.rounds[roundNumber]; ok {
		return
	}
	h.rounds[roundNumber] = r
	h.currentRound = r
	done := make(chan bool)
	//var numReceiveRound int
	wg := sync.WaitGroup{}
	//if party is new party	and the current round is not the output round
	if h.localConn.LocalConfig.IsNewCommittee && r.Number() != 0 {
		//judge if the current round is receiving messages from new party or old party
		MessageFrom := numReceiveRoundMapNewParty[int(r.Number())]
		go func() {
			var msgMap map[party.ID][]byte
			//if MessageFrom == -1, it means that the current round is receiving messages from old party
			if MessageFrom == -1 {
				//call the BroadcastReceiveFromOldparty method to receive messages from old party
				msgMap, err = h.localConn.BroadcastReceiveFromOldparty()
			} else { //if MessageFrom == 1, it means that the current round is receiving messages from new party
				//call the BroadcastReceiveFromNewparty method to receive messages from new party
				msgMap, err = h.localConn.BroadcastReceiveFromNewparty()
			}
			if err != nil {
				log.Errorln("fail BroadcastReceive")
				return
			}
			wg.Add(len(msgMap))
			//iterate over the received messages
			for id, msgByte := range msgMap {
				//process each message in parallel using goroutines.
				go func(id party.ID, msgByte []byte) {
					defer wg.Done()
					tmpMsg := &Message{}
					//unmarshal them into Message structs(tmpMsg)
					err = cbor.Unmarshal(msgByte, tmpMsg)
					if err != nil {
						log.Errorf("fail unmarshal %v", err)
					}
					log.Infof("received from party %v, message is %+v", id, tmpMsg)
					//call the Accept method of the handler to handle the message.
					h.Accept(tmpMsg)
				}(id, msgByte)
			}
			wg.Wait()
			done <- true
		}()
	} else {
		//if party is old party, old party does not need to receive messages.
		go func() {
			done <- true
		}()
	}
reshare:
	for {
		select {
		case <-done:
			// either we get the current round, the next one, or one of the two final ones
			switch R := r.(type) {
			//If it is an Abort round, indicating an error occurred,
			//it calls the abort method with the error and culprits (if any) and returns.
			case *round.Abort:
				h.abort(R.Err, R.Culprits...)
				break reshare
				//it is an Output round, indicating the protocol has produced a result,
				//it assigns the result to the h.result field
				//and calls the abort method without an error to terminate the protocol execution.
			case *round.Output:
				println("output in handler")
				h.result = R.Result
				h.abort(nil)
				break reshare
			default:
			}
			// Recursively call finalize to enter the next round
			h.finalizeReshare()
			break reshare //break the for loop
		}
	}
	return
}

// abort function is used to handle the case when an error occurs.
func (h *MultiHandler) abort(err error, culprits ...party.ID) {
	if err != nil {
		//create an Error object in the handler's err field, which includes the culprits and the err itself.
		h.err = &Error{
			Culprits: culprits,
			Err:      err,
		}
		select {
		//send an error message through the out channel.
		case h.out <- &Message{
			SSID:     h.currentRound.SSID(),
			From:     h.currentRound.SelfID(),
			Protocol: h.currentRound.ProtocolID(),
			Data:     []byte(h.err.Error()),
		}:
		default:
		}

	}
	//close the out channel to indicate that no more messages will be sent.
	close(h.out)
}

// Stop cancels the current execution of the protocol, and alerts the other users.
func (h *MultiHandler) Stop() {
	if h.err != nil || h.result != nil {
		h.abort(errors.New("aborted by user"), h.currentRound.SelfID())
	}
}

// expectsNormalMessage checks if the given round is expected to have normal messages.
func expectsNormalMessage(r round.Session) bool {
	// For the first round, r.MessageContent() will be nil, so it is not expected to have normal messages.
	// For subsequent rounds, r.MessageContent() should return a non-nil value, indicating the presence of normal messages.
	return r.MessageContent() != nil
}

// receivedAll to verify if all messages have been received
func (h *MultiHandler) receivedAll() bool {
	r := h.currentRound
	number := r.Number()
	// Check if all broadcast messages from each party have been received
	if _, ok := r.(round.BroadcastRound); ok {
		log.Infof("round is BroadcastRound" + r.ProtocolID() + string(r.Number()))
		//If h.broadcast[number] is nil, it means that no broadcast messages have been received in the current round
		if h.broadcast[number] == nil {
			return false
		}
		//Iterate over each party id in the current round
		for _, id := range r.PartyIDs() {
			msg := h.broadcast[number][id]
			//If msg is nil, it means that a broadcast message from the corresponding party ID has not been received yet
			if msg == nil {
				return false
			}
		}
		//If h.broadcastHashes[number] is nil,
		//it means that the hash value of broadcast messages in the current round has not been computed yet.
		// Create hash of all message for this round
		if h.broadcastHashes[number] == nil {
			//Create a hash state
			hashState := r.Hash()
			for _, id := range r.PartyIDs() {
				//retrieve the corresponding broadcast message for each party id
				msg := h.broadcast[number][id]
				// write the hash.BytesWithDomain struct into the hash state
				_ = hashState.WriteAny(&hash.BytesWithDomain{
					TheDomain: "Message",
					Bytes:     msg.Hash(),
				})
			}
			//calculate the sum of the hash state
			h.broadcastHashes[number] = hashState.Sum()
		}
	}
	//check whether the current round expects normal messages
	if expectsNormalMessage(r) {
		//If h.messages[number] == nil, it means that the map for storing normal messages
		//in the current round has not been initialized, and the code returns false.
		if h.messages[number] == nil {
			return false
		}
		for _, id := range r.OtherPartyIDs() {
			// h.messages[number][id] == nil means the message from that party has not been received yet, and the code returns false
			if h.messages[number][id] == nil {
				return false
			}
		}
	}
	return true
}

// duplicate method of the MultiHandler struct is used to check whether a received message is a duplicate.
func (h *MultiHandler) duplicate(msg *Message) bool {
	if msg.RoundNumber == 0 {
		return false
	}
	var q map[party.ID]*Message
	if msg.Broadcast {
		// If it is a broadcast message, retrieve the corresponding map of messages for the round from h.broadcast.
		q = h.broadcast[msg.RoundNumber]
	} else {
		// If it is a normal message, retrieve the corresponding map of messages for the round from h.messages.
		q = h.messages[msg.RoundNumber]
	}
	//Technically, receiving a nil message is not considered a duplicate since it is not expected.
	//no messages have been received for the round yet, so the message is not a duplicate
	if q == nil {
		return false
	}
	// Check if the message from the same sender already exists in the map.
	// If it does, it is considered a duplicate.
	return q[msg.From] != nil
}

// store saves the broadcast message or normal message in the corresponding map in h.broadcast or h.messages, respectively.
func (h *MultiHandler) store(msg *Message) {
	var q map[party.ID]*Message
	if msg.Broadcast {
		// If it is a broadcast message, retrieve the corresponding map of messages for the round from h.broadcast.
		q = h.broadcast[msg.RoundNumber]
	} else {
		// If it is a normal message, retrieve the corresponding map of messages for the round from h.messages.
		q = h.messages[msg.RoundNumber]
	}
	// If the map is nil or if a message from the same sender already exists in the map, return without saving the message.
	if q == nil || q[msg.From] != nil {
		return
	}
	// Save the message in the map.
	q[msg.From] = msg
}

// getRoundMessage attempts to unmarshal a raw Message for round `r` in a round.Message.
// The function takes two parameters: msg, which is the raw Message to be unmarshalled,
// and r, which represents the current round session.
// If an error is returned, we should abort.
func getRoundMessage(msg *Message, r round.Session) (round.Message, error) {
	var content round.Content

	// there are two possible content messages
	//check whether the message is a broadcast message
	if msg.Broadcast {
		// cast the round session r to a round.BroadcastRound
		b, ok := r.(round.BroadcastRound)
		if !ok {
			return round.Message{}, errors.New("got broadcast message when none was expected")
		}
		//assign the broadcast content using b.BroadcastContent()
		content = b.BroadcastContent()
	} else {
		//assigns the message content using r.MessageContent().
		content = r.MessageContent()
	}

	//unmarshal the message data (msg.Data) into the content variable
	if err := cbor.Unmarshal(msg.Data, content); err != nil {
		return round.Message{}, fmt.Errorf("failed to unmarshal: %w", err)
	}
	//construct and return a round.Message object using the unmarshalled data, the From and To fields from the raw message, and the broadcast flag.
	roundMsg := round.Message{
		From:      msg.From,
		To:        msg.To,
		Content:   content,
		Broadcast: msg.Broadcast,
	}
	return roundMsg, nil
}

// checkBroadcastHash is run after receivedAll() and checks whether all provided verification hashes are correct.
func (h *MultiHandler) checkBroadcastHash() bool {
	number := h.currentRound.Number()
	//check the hash of the previous round from h.broadcastHashes
	previousHash := h.broadcastHashes[number-1]
	if previousHash == nil {
		return true
	}

	//the function loops over the point-to-point messages in the current round stored in h.messages[number]
	for _, msg := range h.messages[number] {
		if msg != nil && !bytes.Equal(previousHash, msg.BroadcastVerification) {
			return false
		}
	}
	//loop over the broadcast messages in the current round stored in h.broadcast[number]
	for _, msg := range h.broadcast[number] {
		if msg != nil && !bytes.Equal(previousHash, msg.BroadcastVerification) {
			return false
		}
	}
	return true
}

// newQueue creates and initializes a queue structure used for storing messages.
func newQueue(senders []party.ID, rounds round.Number) map[round.Number]map[party.ID]*Message {
	n := len(senders)
	//create an empty map q to store the queue
	q := make(map[round.Number]map[party.ID]*Message, rounds)
	//iterate from round number 2 up to rounds (inclusive).
	for i := round.Number(2); i <= rounds; i++ {
		//create a new map in the q[i] to store messages for that round
		q[i] = make(map[party.ID]*Message, n)
		for _, id := range senders {
			//initialize the corresponding entry（*Message） in the map for the current round to nil
			q[i][id] = nil
		}
	}
	return q
}

// The String method is defined on the MultiHandler struct and returns a string
func (h *MultiHandler) String() string {
	return fmt.Sprintf("party: %s, protocol: %s", h.currentRound.SelfID(), h.currentRound.ProtocolID())
}
