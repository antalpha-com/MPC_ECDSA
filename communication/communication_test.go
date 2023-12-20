// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package communication

import (
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/protocol"
	pb "MPC_ECDSA/proto/MPC_ECDSA/proto"
	"os"
	"path"
	"runtime"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
)

func Chdir1() (err error) {
	err = os.Chdir("../")
	return
}
func getCurrentPath() string {
	_, filename, _, _ := runtime.Caller(1)

	return path.Dir(filename)
}
func TestSetUpConn(t *testing.T) {
	Chdir()
	conn := SetUpConn()
	log.Infof("conn is %+v\n", conn)
}

type Atest struct {
	A string
	B Btest
}

type Btest struct {
	C int32
	D Ctest
}

type Ctest struct {
	F string
}

// TestComplexStruct_Send simulates sending a complex structured message to another party. (b->a)
func TestComplexStruct_Send(t *testing.T) {
	Chdir()
	localConn := SetUpConn()
	oID := 'a'

	var test Atest
	test.A = "sxm"
	test.B.C = 24
	test.B.D.F = "okk"
	//serialize it using CBOR
	data, _ := cbor.Marshal(test)
	log.Infof("test p2p send to %v message = %+v", oID, test)

	err := localConn.P2pSend(party.ID(oID), data)
	if err != nil {
		log.Errorln(err)
		return
	}

}

// TestComplexStruct_Recv simulates receiving a complex structured message from another party.
func TestComplexStruct_Recv(t *testing.T) {
	Chdir()
	localConn := SetUpConn()
	oID := 'b'
	//receive the message using the P2pReceive method of the local connection
	data, err := localConn.P2pReceive(party.ID(oID))
	if err != nil {
		log.Errorln(err)
		return
	}

	//unmarshal the received data into a struct.
	testNew := &Atest{}
	err = cbor.Unmarshal(data, testNew)
	if err != nil {
		log.Errorf("unmarshall err %+v", err)
	}
	log.Infof("testNew is %+v\n", testNew)
}

// TestLocalConn_P2pSend simulates sending a Protobuf message to another party using the local connection
func TestLocalConn_P2pSend(t *testing.T) {
	Chdir()
	localConn := SetUpConn()

	oID := "b"
	message := &pb.HelloRequest{
		Name: "sxm",
		Age:  24,
	}
	//serialize
	data, _ := proto.Marshal(message)
	log.Infof("test p2p send to %v message = %+v", oID, message)
	//send it using the P2pSend method.
	err := localConn.P2pSend(party.ID(oID), data)
	if err != nil {
		log.Errorln(err)
		return
	}
}

// TestLocalConn_P2pReceive simulates receiving a Protobuf message from another party using the local connection.( b send to a)
func TestLocalConn_P2pReceive(t *testing.T) {
	Chdir()

	localConn := SetUpConn()
	oID := "b"
	//receive the message using the P2pReceive method
	data, err := localConn.P2pReceive(party.ID(oID))
	if err != nil {
		log.Errorln(err)
		return
	}

	hello := new(pb.HelloRequest)
	//unmarshal it into a Protobuf message.
	err = proto.Unmarshal(data, hello)
	if err != nil {
		log.Errorln(err)
		return
	}

	log.Infof("hello message is %+v", hello)

}

// TestLocalConn_BroadcastSendRecv simulates broadcasting a message to all other participating parties and receiving the broadcasted messages
func TestLocalConn_BroadcastSendRecv(t *testing.T) {
	Chdir()
	localConn := SetUpConn()
	//initialize a test struct,
	var test Atest
	test.A = string(localConn.LocalConfig.LocalID)
	test.B.C = 24
	test.B.D.F = localConn.LocalConfig.LocalAddr
	//serialize the test
	data, err := cbor.Marshal(test)
	if err != nil {
		log.Errorln("fail Marshal")
	}

	var msgMap map[party.ID][]byte
	go func(msgMap *map[party.ID][]byte) {
		*msgMap, err = localConn.BroadcastReceive()
		if err != nil {
			log.Errorln("fail BroadcastReceive")
			return
		}

		for id, msgByte := range *msgMap {
			newAtest := &Atest{}
			err = cbor.Unmarshal(msgByte, newAtest)
			if err != nil {
				log.Errorln("fail unmarshal")
			}
			log.Infof("party %v received message %+v\n", id, newAtest)
		}

	}(&msgMap)

	err = localConn.BroadcastSend(data)
	if err != nil {
		log.Errorln("fail BroadcastSend")
		return
	}

	time.Sleep(10 * time.Second)

}

// TestLocalConn_BroadcastReceive simulates receiving broadcasted messages from other parties.
func TestLocalConn_BroadcastReceive(t *testing.T) {
	Chdir()
	localConn := SetUpConn()

	receiveMsgMap, err := localConn.BroadcastReceive()
	if err != nil {
		log.Errorln("fail BroadcastReceive")
		return
	}

	msgMap := make(map[party.ID]Atest, len(receiveMsgMap))
	for fromID, byteMsg := range receiveMsgMap {
		newAtest := new(Atest)
		err := cbor.Unmarshal(byteMsg, newAtest)
		if err != nil {
			return
		}
		msgMap[fromID] = *newAtest
		log.Infof("msg from %v is %+v", fromID, newAtest)
	}

}

// TestLocalConn_BigSend simulates sending a large message to another party
func TestLocalConn_BigSend(t *testing.T) {
	Chdir()
	localConn := SetUpConn()
	oID := 'b'
	data := make([]byte, 3)
	log.Infof("test p2p send to %v ,len id %v, message = %+v", oID, len(data), data)

	err := localConn.P2pSend(party.ID(oID), data)
	if err != nil {
		log.Errorln(err)
		return
	}
}

// TestLocalConn_BigReceive simulates receiving a large message from another party
func TestLocalConn_BigReceive(t *testing.T) {
	Chdir()

	localConn := SetUpConn()
	oID := "a"

	data, err := localConn.P2pReceive(party.ID(oID))
	if err != nil {
		log.Errorln(err)
		return
	}
	log.Infof("test p2p receive from %v ,len id %v, message = %+v", oID, len(data), data)

	tmpMsg := &protocol.Message{}
	err = cbor.Unmarshal(data, tmpMsg)
	if err != nil {
		log.Errorf("fail unmarshal %v", err)
	}

	log.Infof("hello message is %+v", tmpMsg)

}
