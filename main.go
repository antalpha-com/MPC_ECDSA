// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

/*
*
The file where main is located, as an example
 1. Establish a TLS connection
 2. Call the implemented interface to complete the following four processes in sequence
 1. Key generation
 2. Key refresh
 3. Pre-signed
 4. signature
*/
package main

import (
	"MPC_ECDSA/communication"
	"MPC_ECDSA/internal/save"
	"MPC_ECDSA/internal/test"
	"MPC_ECDSA/pkg/ecdsa"
	"MPC_ECDSA/pkg/ecdsa3rounds"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pool"
	"MPC_ECDSA/pkg/protocol"
	"MPC_ECDSA/protocols"
	"bufio"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

//var done = make(chan bool)

// printTips() function is responsible for printing a menu of available options for executing different stages of a protocol.
func printTips() {
	fmt.Println("\nConnection is completed, please type the name of stage you want to execute:(e.g. PreSign3 10086)")
	fmt.Println("[-] KeyGen")
	fmt.Println("[-] KeyRefresh")
	fmt.Println("[-] KeyReshare")
	fmt.Println("[-] PreSign3 <presign_id>")
	fmt.Println("[-] SignAfterPreSign3 <presign_id>")
	fmt.Println("[-] PreSign6 <presign_id>")
	fmt.Println("[-] SignAfterPreSign6 <presign_id>")
	fmt.Println("[-] Sign")
	fmt.Println("[-] Ctrl+c to exit")
	fmt.Printf(">>> ")
}

// KeyGen function is responsible for executing the Key Generation stage of the protocol.
// It takes a local connection (localConn), a network (n), and a pool (pl) as input.
func KeyGen(localConn *communication.LocalConn, pl *pool.Pool) error {
	log.Infoln("step into KeyGen func")
	//Retrieve the local ID, party IDs, threshold, and useMnemonic flag from localConn.LocalConfig
	id := localConn.LocalConfig.LocalID
	ids := party.NewIDSlice(localConn.LocalConfig.PartyIDs)
	threshold := localConn.LocalConfig.Threshold
	useMnemonic := localConn.LocalConfig.UseMnemonic
	//Create a new MultiHandler with the Keygen protocol instantiated with the Secp256k1 curve, the local ID, party IDs, threshold, pool, and useMnemonic flag.
	h, err := protocol.NewMultiHandler(protocols.Keygen(curve.Secp256k1{}, id, ids, threshold, pl, useMnemonic), nil, *localConn)
	if err != nil {
		log.Errorln(err)
		return err
	}
	//Handle the protocol execution by calling the Result method on the MultiHandler.
	//This blocks until the protocol execution is complete and returns the result (r) or an error (if any).
	r, err := h.Result()
	if err != nil {
		log.Errorln(err)
		return err
	}
	//Save the protocol configuration (r) to the local connection.
	config := r.(*protocols.Config)
	err = save.SaveKeyGenResult(config)
	if err != nil {
		log.Errorln("fail to save keygen result")
		return err
	}

	log.Infoln("successfully key generation")
	return nil
}

// KeyRefresh function is used to perform the key refresh step.
func KeyRefresh(localConn *communication.LocalConn, pl *pool.Pool) error {
	log.Infoln("step into KeyRefresh func")
	// reload keygen config
	err := localConn.LoadKeyGenConfig()
	if err != nil {
		log.Errorln("fail to load keygen config")
		return err
	}
	log.Infoln("reload keygen config success")

	// load keygen result from fixture file
	config, err := save.LoadKeyGenResult()
	if err != nil {
		log.Errorln("fail to load keygen result")
		return err
	}
	log.Infoln("load previous keygen config success")
	//Create a new MultiHandler object (hRefresh) with the protocol configuration and the connection pool, to execute the refresh protocol.
	hRefresh, err := protocol.NewMultiHandler(protocols.Refresh(config, pl), nil, *localConn)
	if err != nil {
		log.Errorln(err)
		return err
	}
	//Check the result of the refresh protocol execution
	r, err := hRefresh.Result()
	if err != nil {
		log.Errorln(err)
		return err
	}
	//Save the protocol configuration (r) to the local connection.
	refreshConfig := r.(*protocols.Config)
	err = save.SaveKeyGenResult(refreshConfig)
	if err != nil {
		log.Errorln("fail to save keygen result")
		return err
	}
	log.Infoln("successfully key refresh")
	return nil
}

// KeyRefresh function performs the (t,n)key-resharing step for a specific protocol.
func KeyReshare(localConn *communication.LocalConn, pl *pool.Pool) error {
	log.Infoln("step into KeyResharing func")
	err := localConn.LoadRefreshConfig()
	if err != nil {
		log.Errorln("fail to load keygen config")
		//return err
	}
	log.Infoln("reload resharing config success")
	var Myconfig interface{}
	if localConn.LocalConfig.IsOldCommittee {
		Myconfig, _ = save.LoadKeyGenResult2()
		if err != nil {
			log.Errorln("fail to load keygen result")
		}
		log.Infoln("load previous keygen config success")
	} else {
		Myconfig = nil
	}
	hReshare, err := protocol.NewMultiHandlerReshare(protocols.Resharing(localConn, pl, Myconfig), nil, *localConn)
	//hReshare, err := protocol.NewMultiHandlerReshare(nil, nil, *localConn)
	if err != nil {
		log.Errorln(err)
		return err
	}
	//Check the result of the refresh protocol execution
	r, err := hReshare.Result()
	if err != nil {
		log.Errorln(err)
		return err
	}
	//Save the protocol configuration (r) to the local connection.
	reshareConfig := r.(*protocols.Config)
	//user can save reshare result to keygen result file or refresh result file
	//err = save.SaveKeyGenResult(reshareConfig)
	err = save.SaveReshareResult(reshareConfig)

	if err != nil {
		log.Errorln("fail to save keygen result")
		return err
	}
	log.Infoln("successfully key resharing")
	return nil
}

// PreSign3rounds function performs the pre-signing step for a specific protocol.
func PreSign3rounds(localConn *communication.LocalConn, presignID string, pl *pool.Pool) error {
	log.Infoln("step into PreSign3rounds func")
	// reload sign config
	err := localConn.LoadSignConfig()
	if err != nil {
		log.Errorln("fail to load sign config")
		return err
	}
	log.Infoln("reload sign config success")
	log.Infof("presign signers is %+v\n", localConn.LocalConfig.Signers)
	// Get the signers participating in the signature
	signers := party.NewIDSlice(localConn.LocalConfig.Signers)
	//retrieve the local ID
	id := localConn.LocalConfig.LocalID
	if !signers.Contains(id) {
		log.Infoln("Not a signatory participant, exit")
		return nil
	}
	// load keygen result from fixture file
	config, err := save.LoadKeyGenResult()
	if err != nil {
		log.Errorln("fail to load keygen result")
		return err
	}
	log.Infoln("load previous keygen config success")
	//Create a new MultiHandler for the Presign protocol
	h, err := protocol.NewMultiHandler(protocols.Presign3rounds(config, signers, pl), nil, *localConn) //handler表示一个协议的执行
	if err != nil {
		log.Errorln(err)
		return err
	}
	// Get the result of the protocol execution
	preSignResult, err := h.Result()
	if err != nil {
		log.Errorln(err)
		return err
	}
	//convert the result from the interface type to the specific PreSignature type.
	preSignature := preSignResult.(*ecdsa3rounds.PreSignature3)
	// Validate the pre-signature
	if err = preSignature.Validate(); err != nil {
		log.Errorln("failed to verify cmp presignature")
		return err
	}
	// save presign result to fixture file
	err = save.SavePresign3Result(preSignature, presignID)
	if err != nil {
		log.Errorln("fail to save presign result")
		return err
	}
	log.Infoln("successfully presSign")
	return nil
}

// SignAfterPreSign3rounds function performs the signing operation after the pre-signing stage.
func SignAfterPreSign3rounds(localConn *communication.LocalConn, presignID string, pl *pool.Pool) error {
	log.Infoln("step into SignAfterPreSign3rounds func, presignID is ", presignID)
	// load keygen result from fixture file
	config, err := save.LoadKeyGenResult()
	if err != nil {
		log.Errorln("fail to load keygen result")
		return err
	}
	log.Infoln("load previous keygen config success")
	// Get the signers participating in the signature
	signers := party.NewIDSlice(localConn.LocalConfig.Signers)
	//obtain the message to sign
	message := []byte(localConn.LocalConfig.MessageToSign)
	//retrieve the pre-signature
	preSignature, err := save.LoadPresign3Result(presignID)
	if err != nil {
		log.Errorln("fail to load presign result")
		return err
	}
	//create a new multihandler (h) using the SignAfterPresign protocol
	h, err := protocol.NewMultiHandler(protocols.SignAfterPresign3rounds(config, signers, preSignature, message, pl), nil, *localConn)
	if err != nil {
		return err
	}

	//retrieve the sign result
	signResult, err := h.Result()
	if err != nil {
		log.Errorln("SignAfterPreSign: failed to get signResult")
		return err
	}
	signature := signResult.(*ecdsa3rounds.Signature)
	//verify the signature
	if !signature.Verify(config.PublicPoint(), message) {
		log.Errorln("SignAfterPreSign: failed to verify cmp signature")
		return errors.New("failed to verify cmp signature")
	}

	log.Infoln("successfully sign message after presign")
	// delete presign result from fixture file after use
	err = save.DeletePreSign3Result(presignID)
	if err != nil {
		log.Errorf("fail to delete presign result, err is %v", err)
	}
	log.Infoln("successfully delete presign result")
	return nil
}

// PreSign6rounds function performs the pre-signing step for a specific protocol.
func PreSign6rounds(localConn *communication.LocalConn, presignID string, pl *pool.Pool) error {
	log.Infoln("step into PreSign6rounds func")
	// reload sign config
	err := localConn.LoadSignConfig()
	if err != nil {
		log.Errorln("fail to load sign config")
		return err
	}
	log.Infoln("reload sign config success")
	log.Infof("presign signers is %+v\n", localConn.LocalConfig.Signers)
	// Get the signers participating in the signature
	signers := party.NewIDSlice(localConn.LocalConfig.Signers)
	//retrieve the local ID
	id := localConn.LocalConfig.LocalID
	if !signers.Contains(id) {
		log.Infoln("Not a signatory participant, exit")
		return nil
	}
	// load keygen result from fixture file
	config, err := save.LoadKeyGenResult()
	if err != nil {
		log.Errorln("fail to load keygen result")
		return err
	}
	log.Infoln("load previos keygen config success")
	//Create a new MultiHandler for the Presign protocol
	h, err := protocol.NewMultiHandler(protocols.Presign(config, signers, pl), nil, *localConn)
	if err != nil {
		log.Errorln(err)
		return err
	}
	// Get the result of the protocol execution
	preSignResult, err := h.Result()
	if err != nil {
		log.Errorln(err)
		return err
	}
	//convert the result from the interface type to the specific PreSignature type.
	preSignature := preSignResult.(*ecdsa.PreSignature)
	// Validate the pre-signature
	if err = preSignature.Validate(); err != nil {
		log.Errorln("failed to verify cmp presignature")
		return err
	}
	// save presign result to fixture file
	if err = save.SavePresign6Result(preSignature, presignID); err != nil {
		log.Errorln("fail to save presign result")
		return err
	}
	log.Infoln("successfully presSign")
	return nil
}

// SignAfterPreSign6rounds function performs the signing operation after the pre-signing stage.
func SignAfterPreSign6rounds(localConn *communication.LocalConn, presignID string, pl *pool.Pool) error {
	log.Infoln("step into SignAfterPreSign6rounds func")
	// load keygen result from fixture file
	config, err := save.LoadKeyGenResult()
	if err != nil {
		log.Errorln("fail to load keygen result")
		return err
	}
	log.Infoln("load previos keygen config success")
	//obtain the message to sign
	message := []byte(localConn.LocalConfig.MessageToSign)
	//retrieve the pre-signature
	preSignature, err := save.LoadPresign6Result(presignID)
	if err != nil {
		log.Errorln("fail to load presign result")
		return err
	}
	//create a new multihandler (h) using the SignAfterPresign protocol
	h, err := protocol.NewMultiHandler(protocols.SignAfterPresign(config, preSignature, message, pl), nil, *localConn)
	if err != nil {
		return err
	}

	//retrieve the sign result
	signResult, err := h.Result()
	if err != nil {
		log.Errorln("SignAfterPreSign: failed to get signResult")
		return err
	}
	signature := signResult.(*ecdsa.Signature)
	//verify the signature
	if !signature.Verify(config.PublicPoint(), message) {
		log.Errorln("SignAfterPreSign: failed to verify cmp signature")
		return errors.New("failed to verify cmp signature")
	}

	log.Infoln("successfully sign message after presign")
	// delete presign result from fixture file after use
	err = save.DeletePreSign6Result(presignID)
	if err != nil {
		log.Errorf("fail to delete presign result, err is %v", err)
	}
	log.Infoln("successfully delete presign result")
	return nil
}

// Sign function performs the signing operation
func Sign(localConn *communication.LocalConn, net *test.Network, pl *pool.Pool) error {
	log.Infoln("step into Sign func")
	// reload sign config
	err := localConn.LoadSignConfig()
	if err != nil {
		return err
	}
	log.Infoln("reload sign config success")
	// load keygen result from fixture file
	config, err := save.LoadKeyGenResult()
	if err != nil {
		log.Errorln("fail to load keygen result")
		return err
	}
	log.Infoln("load previos keygen config success")
	signers := party.NewIDSlice(localConn.LocalConfig.Signers)
	message := []byte(localConn.LocalConfig.MessageToSign)
	// create a new multi-handler (h) using the Sign protocol
	h, err := protocol.NewMultiHandler(protocols.Sign(config, signers, message, pl), nil, *localConn)
	if err != nil {
		log.Errorln(err)
		return err
	}
	//retrieve the sign result from the multi-handler
	signResult, err := h.Result()
	if err != nil {
		log.Errorln(err)
		return err
	}
	signature := signResult.(*ecdsa.Signature)
	//verify the signature
	if !signature.Verify(config.PublicPoint(), message) {
		log.Errorln("failed to verify cmp signature")
		return errors.New("failed to verify cmp signature")
	}
	log.Infoln("successfully sign message")
	return nil
}

// The stepIntoStage function is responsible for executing the specific logic corresponding to the given stage of the protocol.
// It takes a local connection (localConn), a stage string, a network (net), and a pool (pl) as input.
func stepIntoStage(localConn *communication.LocalConn, stageString string, net *test.Network, pl *pool.Pool) error {
	// split stage into []string
	stageAfterSplit := strings.Split(stageString, " ")
	if len(stageAfterSplit) == 0 || len(stageAfterSplit) > 2 {
		// if the length of stageAfterSplit is 0 or greater than 2, it means that the stage is wrong
		log.Errorln("wrong stage name, please check")
		return nil
	}
	// print stageAfterSplit
	log.Infof("stageAfterSplit is %+v\n", stageAfterSplit)
	// stage means the first element of stageAfterSplit
	stage := stageAfterSplit[0]
	//Use a switch statement to determine the stage of the protocol based on the given stage string.
	switch stage {
	case "KeyGen":
		//Call the KeyGen function to execute the protocol logic for KeyGen
		err := KeyGen(localConn, pl)
		if err != nil {
			log.Errorln("fail KeyGen")
			return err
		}
		break
	case "KeyRefresh":
		//Call the KeyRefresh function to execute the protocol logic for KeyRefresh
		err := KeyRefresh(localConn, pl)
		if err != nil {
			log.Errorln("fail KeyRefresh")
			return err
		}
		break

	case "KeyReshare":
		//Call the KeyRefresh function to execute the protocol logic for KeyRefresh
		err := KeyReshare(localConn, pl)
		if err != nil {
			log.Errorln("fail KeyRefresh")
			return err
		}
		break
	case "PreSign3":
		presignID := stageAfterSplit[1]
		//Call the PreSign function to execute the protocol logic for PreSign
		err := PreSign3rounds(localConn, presignID, pl)
		if err != nil {
			log.Errorln("fail PreSign3rounds")
			return err
		}
		break
	case "SignAfterPreSign3":
		presignID := stageAfterSplit[1]
		//Call the SignAfterPreSign function to execute the protocol logic for SignAfterPreSign
		err := SignAfterPreSign3rounds(localConn, presignID, pl)
		if err != nil {
			log.Errorln("fail SignAfterPreSign3")
			return err
		}
		break
	case "PreSign6":
		presignID := stageAfterSplit[1]

		//Call the PreSign function to execute the protocol logic for PreSign
		err := PreSign6rounds(localConn, presignID, pl)
		if err != nil {
			log.Errorln("fail PreSign3rounds")
			return err
		}
		break
	case "SignAfterPreSign6":
		presignID := stageAfterSplit[1]
		//Call the SignAfterPreSign function to execute the protocol logic for SignAfterPreSign
		err := SignAfterPreSign6rounds(localConn, presignID, pl)
		if err != nil {
			log.Errorln("fail SignAfterPreSign3")
			return err
		}
		break
	case "Sign":
		//Call the Sign function to execute the protocol logic for Sign
		err := Sign(localConn, net, pl)
		if err != nil {
			log.Errorln("fail Sign")
			return err
		}
		break
	default:
		log.Errorln("wrong stage name, please check")
		break
	}
	return nil
}

// The execute function is responsible for executing the protocol logic based on the stage of the protocol.
// It takes a local connection (localConn) and a pool (pl) as input.
func execute(localConn *communication.LocalConn, pl *pool.Pool) error {
	// Get the center server ID and local ID from the local connection's configuration.
	centerID := localConn.LocalConfig.CenterServerID
	localID := localConn.LocalConfig.LocalID

	//  Determine the stage of the protocol based on whether the local ID matches the center server ID.
	//If they match, it means that the local participant is responsible for initiating the protocol.
	var stage string
	if centerID == localID {
		//If the local ID is the center server ID, prompt the user to enter the stage of the protocol.
		//Print tips:
		printTips()
		//Read the input from the command line and store it in the variable "stage".
		reader := bufio.NewReader(os.Stdin)
		result, _, err := reader.ReadLine()
		if err != nil {
			log.Errorln("fail to read stage from command line")
		}
		stage = string(result)

		//Broadcast the stage instruction to all participants
		err = localConn.BroadcastSend(result)
		if err != nil {
			log.Errorln("fail to BroadcastSend")
			return err
		}
		log.Infof("step into stage %v", stage)

	} else {
		//If the local ID is not the center server ID, listen for instructions from the center server.
		//Receive the data from the center server using localConn.P2pReceive() and store it in the variable "data".
		//The received data represents the current stage of the protocol.
		data, err := localConn.P2pReceive(centerID)
		if err != nil {
			log.Errorf("fail to receive instruction from center server %v", centerID)
			return err
		}

		stage = string(data[:])
		log.Infof("step into stage %v", stage)
	}
	//Create a new network using test.NewNetwork() with the participant IDs and local connection.
	ids := party.NewIDSlice(localConn.LocalConfig.PartyIDs)
	net := test.NewNetwork(ids, localConn)
	//Call the stepIntoStage function to perform the protocol steps corresponding to the stage
	// may be KeyGen, KeyRefresh, PreSign3 <id>, SignAfterPreSign3 <id>, Sign etc.
	stepIntoStage(localConn, stage, net, pl)
	return nil
}

// The main function is the entry point of the program.
func main() {
	//Establish a network connection with other participants.
	//The returned value localConn represents the local connection to the network.

	localConn := communication.SetUpConn()

	//New and old parties establish a key reshare connection.
	//localConn := communication.SetUpConnReshare()

	//Continuously run the protocol in a loop.
	for {
		//Create a new pool pl
		pl := pool.NewPool(0)

		defer pl.TearDown()
		//Call the execute function passing the local connection and the pool as arguments
		err := execute(&localConn, pl)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
}
