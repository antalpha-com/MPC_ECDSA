package test

import (
	"MPC_ECDSA/internal/round"
	"MPC_ECDSA/pkg/party"
	"errors"
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/sync/errgroup"
)

// Rule describes various hooks that can be applied to a protocol execution.
type Rule interface {
	// ModifyBefore modifies r before r.Finalize() is called.
	ModifyBefore(r round.Session)
	// ModifyAfter modifies rNext, which is the round returned by r.Finalize().
	ModifyAfter(rNext round.Session)
	// ModifyContent modifies content for the message that is delivered in rNext.
	ModifyContent(rNext round.Session, to party.ID, content round.Content)
}

// Rounds that executes a series of rounds (round.Session) and applies a specified rule (Rule) to them.
func Rounds(rounds []round.Session, rule Rule) (error, bool) {
	var (
		err       error
		roundType reflect.Type
		errGroup  errgroup.Group
		N         = len(rounds)
		out       = make(chan *round.Message, N*(N+1))
	)
	//check if all rounds belong to the same type
	if roundType, err = checkAllRoundsSame(rounds); err != nil {
		return err, false
	}
	// get the second set of messages
	for id := range rounds {
		idx := id
		r := rounds[idx]
		//create an errGroup to handle the processing of each round concurrently.
		errGroup.Go(func() error {
			var rNew, rNewReal round.Session
			if rule != nil {
				rReal := getRound(r)
				rule.ModifyBefore(rReal)
				//If a rule object exists, creating a new round object and sending the result to the outFake channel.
				outFake := make(chan *round.Message, N+1)
				rNew, err = r.Finalize(outFake)
				close(outFake)
				rNewReal = getRound(rNew)
				rule.ModifyAfter(rNewReal)
				//Send messages from the outFake channel to the out channel.
				for msg := range outFake {
					rule.ModifyContent(rNewReal, msg.To, getContent(msg.Content))
					out <- msg
				}
			} else { //if no rule object exists, directly calling the Finalize method of the round object and sending the result to the out channel.
				rNew, err = r.Finalize(out)
			}

			if err != nil {
				return err
			}

			if rNew != nil {
				rounds[idx] = rNew
			}
			return nil
		})
	}
	//wait for all processing operations to complete and checks if any errors occurred.
	if err = errGroup.Wait(); err != nil {
		return err, false
	}
	//close the out channel.
	close(out)

	// Check that all rounds are the same type
	if roundType, err = checkAllRoundsSame(rounds); err != nil {
		return err, false
	}
	//If the round type is round.Output or round.Abort, it means that the protocol has been completed, and nil and true are returned.
	if roundType.String() == reflect.TypeOf(&round.Output{}).String() {
		return nil, true
	}
	if roundType.String() == reflect.TypeOf(&round.Abort{}).String() {
		return nil, true
	}
	//iterate through the messages in the out channel
	for msg := range out {
		//Serialize the content of the message into bytes.
		msgBytes, err := cbor.Marshal(msg.Content)
		if err != nil {
			return err, false
		}
		for _, r := range rounds {
			m := *msg
			r := r
			//If the sender of the message is the same as the current participant of the round （msg.From == r.SelfID()）
			//or the round number of the message does not match the round number of the current round, （msg.Content.RoundNumber() != r.Number()）
			//it skips that round.
			if msg.From == r.SelfID() || msg.Content.RoundNumber() != r.Number() {
				continue
			}
			errGroup.Go(func() error {
				if m.Broadcast { //if the message is a broadcast message
					b, ok := r.(round.BroadcastRound)
					if !ok {
						return errors.New("broadcast message but not broadcast round")
					}
					//replace the message content with the broadcast content
					m.Content = b.BroadcastContent()
					//deserialize the bytes into the new content.
					if err = cbor.Unmarshal(msgBytes, m.Content); err != nil {
						return err
					}

					if err = b.StoreBroadcastMessage(m); err != nil {
						return err
					}
				} else {
					m.Content = r.MessageContent()
					if err = cbor.Unmarshal(msgBytes, m.Content); err != nil {
						return err
					}
					//If the receiver of the message is empty（m.To == "" ）
					//or the same as the current participant of the round（m.To == r.SelfID()）
					if m.To == "" || m.To == r.SelfID() {
						//Verify the validity of the message.
						if err = r.VerifyMessage(m); err != nil {
							return err
						}
						//Store the message in the round object.
						if err = r.StoreMessage(m); err != nil {
							return err
						}
					}
				}

				return nil
			})
		}
		//wait for all processing operations to complete
		if err = errGroup.Wait(); err != nil {
			return err, false
		}
	}
	return nil, false
}
func RoundsResharing(rounds []round.Session, rule Rule) (error, bool) {
	var (
		err       error
		roundType reflect.Type
		errGroup  errgroup.Group
		N         = len(rounds)
		out       = make(chan *round.Message, N*(N+1))
	)
	//check if all rounds belong to the same type
	if roundType, err = checkAllRoundsSame(rounds); err != nil {
		return err, false
	}
	// get the second set of messages
	for id := range rounds {
		idx := id
		r := rounds[idx]
		//create an errGroup to handle the processing of each round concurrently.
		errGroup.Go(func() error {
			var rNew, rNewReal round.Session
			if rule != nil {
				rReal := getRound(r)
				rule.ModifyBefore(rReal)
				//If a rule object exists, creating a new round object and sending the result to the outFake channel.
				outFake := make(chan *round.Message, N+1)
				rNew, err = r.Finalize(outFake)
				close(outFake)
				rNewReal = getRound(rNew)
				rule.ModifyAfter(rNewReal)
				//Send messages from the outFake channel to the out channel.
				for msg := range outFake {
					rule.ModifyContent(rNewReal, msg.To, getContent(msg.Content))
					out <- msg
				}
			} else { //if no rule object exists, directly calling the Finalize method of the round object and sending the result to the out channel.
				rNew, err = r.Finalize(out)
			}
			if err != nil {
				return err
			}

			if rNew != nil {
				rounds[idx] = rNew
			}
			return nil
		})
	}
	//wait for all processing operations to complete and checks if any errors occurred.
	if err = errGroup.Wait(); err != nil {
		return err, false
	}
	//close the out channel.
	close(out)

	// Check that all rounds are the same type
	if roundType, err = checkAllRoundsSame(rounds); err != nil {
		return err, false
	}
	//If the round type is round.Output or round.Abort, it means that the protocol has been completed, and nil and true are returned.
	if roundType.String() == reflect.TypeOf(&round.Output{}).String() {
		return nil, true
	}
	if roundType.String() == reflect.TypeOf(&round.Abort{}).String() {
		return nil, true
	}
	//iterate through the messages in the out channel
	for msg := range out {
		//iterate through the rounds in the rounds slice
		for _, r := range rounds {
			m := *msg
			r := r
			//If the sender of the message is the same as the current participant of the round （msg.From == r.SelfID()）
			//or the round number of the message does not match the round number of the current round, （msg.Content.RoundNumber() != r.Number()）
			//it skips that round.
			if msg.From == r.SelfID() || msg.Content.RoundNumber() != r.Number() {
				continue
			}
			errGroup.Go(func() error {
				if m.To == "" || m.To == r.SelfID() {
					//Verify the validity of the message.
					if err = r.VerifyMessage(m); err != nil {
						return err
					}
					//Store the message in the round object.
					if err = r.StoreMessage(m); err != nil {
						return err
					}
				}
				return nil
			})
		}
		//wait for all processing operations to complete
		if err = errGroup.Wait(); err != nil {
			return err, false
		}
	}
	return nil, false
}

// checkAllRoundsSame is used to check if all rounds in the given slice have the same type and returns that type
func checkAllRoundsSame(rounds []round.Session) (reflect.Type, error) {
	//Declare a variable t to store the type (reflect.Type) of the rounds.
	var t reflect.Type
	for _, r := range rounds {
		//obtain the actual type rReal of the round r.
		rReal := getRound(r)
		//get the type t2 of rReal.
		t2 := reflect.TypeOf(rReal)
		if t == nil {
			t = t2
		} else if t != t2 {
			return t, fmt.Errorf("two different rounds: %s %s", t, t2)
		}
	}
	return t, nil
}

func getRound(outerRound round.Session) round.Session {
	return outerRound
}

func getContent(outerContent round.Content) round.Content {
	return outerContent
}
