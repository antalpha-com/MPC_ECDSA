// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package communication

import (
	"MPC_ECDSA/pkg/party"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type ID string
type Party struct {
	ID       string `json:"id"`
	Address  string `json:"addr"`
	ConnRole string `json:"connRole"`
}

// LocalConfig struct represents the local configuration for the application.
type LocalConfig struct {
	//Represents the ID of the local party.
	LocalID party.ID `json:"localID"`
	//Represents the address of the local party for establishing connections.
	LocalAddr string `json:"localAddr"`
	//Represents the total number of parties involved in the protocol.
	TotalPartyCount int `json:"totalPartyCount"`
	//Indicates whether the local party can act as a server for establishing connections.
	LocalCanBeServer bool `json:"localCanBeServer"`
	//Represents information about other parties involved in the protocol.
	OtherPartyInfo []Party `json:"otherPartyInfo"`
	//Represents a list of party IDs of the other parties involved.
	OtherPartyIDs []party.ID `json:"otherPartyIDs"`
	//Represents the file path to the certificate authority (CA) file.
	CaPath string `json:"caPath"`
	//Represents the file path to the client certificate file.
	ClientCertPath string `json:"clientCertPath"`
	//Represents the file path to the server certificate file.
	ServerCertPath string `json:"serverCertPath"`
	//Represents the file path to the server private key file.
	ServerKeyPath string `json:"serverKeyPath"`
	//Represents the timeout duration in seconds for network operations.
	TimeOutSecond int `json:"timeOutSecond"`
	//Represents the ID of the center server.
	CenterServerID party.ID `json:"centerServerID"`

	//Represents a list of all party IDs involved in the protocol.
	PartyIDs []party.ID `json:"partyIDs"`

	// keygen Config
	//Indicates whether mnemonic phrases are used for key generation.
	UseMnemonic bool `json:"useMnemonic"`
	//Represents the threshold value used in the protocol.
	Threshold int `json:"threshold"`

	// refresh config
	// new threshold used in reshare, will replace the old threshold
	NewThreshold int `json:"newThreshold"`
	// number of previous parties
	OldPartyCount int `json:"oldPartyCount"`
	// IDs of previos parties
	OldPartyIDs []party.ID `json:"oldPartyIDs"`
	// number of new parties
	NewPartyCount int `json:"newPartyCount"`
	// IDs of new parties
	NewPartyIDs []party.ID `json:"newPartyIDs"`
	// Indicates whether the local party is an old party.
	IsOldCommittee bool `json:"isOldCommittee"`
	// Indicates whether the local party is a new party.
	IsNewCommittee bool `json:"isNewCommittee"`

	// sign config
	//Represents a list of party IDs that are designated as signers.
	Signers []party.ID `json:"signers"`
	//Represents the message that needs to be signed.
	MessageToSign string `json:"messageToSign"`
}

type LocalConn struct {
	LocalConfig   LocalConfig
	IDConnMap     map[party.ID]net.Conn
	Config        interface{}
	PreSign3      interface{}
	PreSignRecord interface{}
	PreSign6      interface{}
}

// LoadCertPool function loads a certificate authority (CA) file and creates a new x509.CertPool
func LoadCertPool(caFile string) (*x509.CertPool, error) {
	// Read the content of the CA file
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	// Create a new CertPool
	pool := x509.NewCertPool()
	// Append the certificates from the PEM content to the CertPool
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("pool append certs from pem failed")
	}
	return pool, nil
}

// LoadTLSConfig function loads a TLS configuration by loading a certificate authority (CA) file, a certificate file, and a key file
func LoadTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	// Load the certificate pool from the CA file
	pool, err := LoadCertPool(caFile)
	if err != nil {
		return nil, fmt.Errorf("load cert pool from (%s): %v", caFile, err)
	}
	// Load the X.509 key pair from the certificate and key files
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load x509 key pair from (%s, %s): %v", certFile, keyFile, err)
	}
	// Create a new TLS config with the loaded certificate pool and key pair
	cfg := &tls.Config{
		//RootCAs and ClientCAs are set to the loaded certificate pool.
		RootCAs:   pool,
		ClientCAs: pool,
		//ClientAuth is set to tls.RequireAndVerifyClientCert, which requires and verifies the client certificate.
		ClientAuth: tls.RequireAndVerifyClientCert,
		//MinVersion is set to tls.VersionTLS12, indicating the minimum TLS version to use.
		MinVersion: tls.VersionTLS12,
		//Certificates is set to an array containing the loaded certificate.
		Certificates: []tls.Certificate{cert},
	}
	return cfg, nil
}

// The StartServer function is used to establish connections between parties.
func (connConf *LocalConn) StartServer() error {
	log.Infoln("start build connection between parties")
	timeOut := connConf.LocalConfig.TimeOutSecond
	//set a timeout for the context to ensure the function doesn't run indefinitely.
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Duration(timeOut)*time.Second)
	defer cancelCtx()

	//load the TLS configuration
	tlsConfig, err := LoadTLSConfig(connConf.LocalConfig.CaPath, connConf.LocalConfig.ServerCertPath, connConf.LocalConfig.ServerKeyPath)
	if err != nil {
		log.Errorln("fail load TLS config")
		return err
	}

	// retrieve localID，otherIDs，parties，and otherPartyNum from the connConf.LocalConfig.
	localID := connConf.LocalConfig.LocalID
	otherIDs := connConf.LocalConfig.OtherPartyIDs
	parties := connConf.LocalConfig.OtherPartyInfo
	otherPartyNum := connConf.LocalConfig.TotalPartyCount - 1

	connMap := make(map[party.ID]net.Conn)

	//create a channel  to control when to return from the function.
	ch := make(chan struct{}, 1)
	//doneConnPartyNum := 0

	// Establish connections as a client
	for index, oID := range otherIDs {
		// If the other party is a server, this party needs to dial as a client
		if parties[index].ConnRole == "server" {
			// Start a goroutine to act as a client and handle sending
			go func(index int, oID party.ID) {
				log.Infof("begin dial and write %v", oID)
				var conn net.Conn
				for {
					log.Infof("dial id = %v, addr = %v", oID, parties[index].Address)
					conn, err = tls.Dial("tcp", parties[index].Address, tlsConfig)

					if err == nil {
						break
					}

				}
				// Send its own ID to the other party
				for {
					log.Infof("writing local ID %v to %v", localID, oID)
					_, err = conn.Write([]byte(localID))
					if err != nil {
						log.Errorln("fail write local ID")
						panic(err)
					}
					log.Infof("successfully connect to %v", oID)
					//add the connection to the connMap
					connMap[oID] = conn
					break
				}
				log.Infoln("done dial and write")

			}(index, oID)

		}
	}

	// Start a goroutine as a server to accept connection requests
	// If there's no fixed IP, this party cannot be a server, so it cannot listen
	if connConf.LocalConfig.LocalCanBeServer {
		go func(ctx context.Context) {
			buf := make([]byte, 1024)
			// Listen for connections
			listener, err := tls.Listen("tcp", connConf.LocalConfig.LocalAddr, tlsConfig)
			if err != nil {
				log.Errorln("fail listen tcp")
			}

			log.Infof("start listen %v\n", connConf.LocalConfig.LocalID)
			defer listener.Close()

			var otherID party.ID
			for {
				//accept a new connection
				conn, err := listener.Accept()
				if err != nil {
					log.Errorln("fail read Accept")
				}
				log.Infoln("accept success")
				//read the other party's ID from the connection
				n, err := conn.Read(buf)
				if err != nil {
					log.Errorln("fail read otherID ID")
					panic(err)
				}
				//The ID is extracted from the received bytes.
				otherID = party.ID(buf[:n])

				log.Infof("successfully connect to %v", otherID)
				//add the connection to the connMap
				connMap[otherID] = conn
			}
		}(ctx)
	}

	go func() {
		//wait until all expected connections from other parties are established
		for {
			if len(connMap) == otherPartyNum {
				time.Sleep(5 * time.Second)
				ch <- struct{}{}
			}
		}

	}()

	select {
	case <-ch: //If a value is received from the ch channel, it means that all connections are set up successfully
		log.Infof("parties set up  %v connections", otherPartyNum)
		connConf.IDConnMap = connMap

	case <-ctx.Done(): //If the ctx.Done() channel is closed, it means that the timeout specified in the context has elapsed.
		log.Errorln("timeout")
		return err
	}

	return nil
}

// LoadConnConfig method is responsible for loading the connection configuration
func (connConf *LocalConn) LoadConnConfig() error {
	jsonFile, err := os.Open("./config/connConfig.json")
	if err != nil {
		log.Errorln("fail open connConfig.json")
		return err
	}
	log.Infoln("successfully open connConfig.json")
	defer jsonFile.Close()

	// Read the contents of the file
	byteValue, _ := io.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &connConf.LocalConfig)
	if err != nil {
		log.Errorln("fail unmarshal connConfig.json")
		return err
	}
	log.Infoln("done unmarshal connConfig")
	return nil
}

// LoadConnConfig method is responsible for loading the connection configuration
func (connConf *LocalConn) LoadConnConfigReshare() error {
	jsonFile, err := os.Open("./config/connConfigReshare.json")
	if err != nil {
		log.Errorln("fail open connConfigReshare.json")
		return err
	}
	log.Infoln("successfully open connConfigReshare.json")
	defer jsonFile.Close()

	// Read the contents of the file
	byteValue, _ := io.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &connConf.LocalConfig)
	if err != nil {
		log.Errorln("fail unmarshal connConfig.json")
		return err
	}
	log.Infoln("done unmarshal connConfig")
	return nil
}

// LoadKeyGenConfig method is responsible for loading the keygen configuration
func (connConf *LocalConn) LoadKeyGenConfig() error {
	jsonFile, err := os.Open("./config/keygenConfig.json")
	if err != nil {
		log.Errorln("fail open keygenConfig.json")
		return err
	}
	log.Infoln("successfully open keygenConfig.json")
	defer jsonFile.Close()
	// Read the contents of the file
	byteValue, _ := io.ReadAll(jsonFile)

	// Unmarshal the JSON data into the LocalConfig struct of the LocalConn instance
	tmpConf := &LocalConfig{}
	err = json.Unmarshal(byteValue, tmpConf)
	if err != nil {
		log.Errorln("fail unmarshal keygenConfig.json")
		return err
	}
	connConf.LocalConfig.Threshold = tmpConf.Threshold
	connConf.LocalConfig.UseMnemonic = tmpConf.UseMnemonic
	log.Infoln("done unmarshal keygenConfig and add new config item to localconn")
	return nil
}

// LoadRefreshConfig method is responsible for loading the refresh configuration
func (connConf *LocalConn) LoadRefreshConfig() error {
	jsonFile, err := os.Open("./config/refreshConfig.json")
	if err != nil {
		log.Errorln("fail open refreshConfig.json")
		return err
	}
	log.Infoln("successfully open refreshConfig.json")
	defer jsonFile.Close()
	// Read the contents of the file
	byteValue, _ := io.ReadAll(jsonFile)

	// Unmarshal the JSON data into the LocalConfig struct of the LocalConn instance
	tmpConf := &LocalConfig{}
	err = json.Unmarshal(byteValue, tmpConf)
	if err != nil {
		log.Errorln("fail unmarshal refreshConfig.json")
		return err
	}
	// update the local config
	connConf.LocalConfig.OldPartyCount = tmpConf.OldPartyCount
	connConf.LocalConfig.OldPartyIDs = tmpConf.OldPartyIDs
	connConf.LocalConfig.NewPartyCount = tmpConf.NewPartyCount
	connConf.LocalConfig.NewPartyIDs = tmpConf.NewPartyIDs
	connConf.LocalConfig.NewThreshold = tmpConf.NewThreshold
	connConf.LocalConfig.IsOldCommittee = tmpConf.IsOldCommittee
	connConf.LocalConfig.IsNewCommittee = tmpConf.IsNewCommittee

	log.Infoln("done unmarshal refreshConfig and add new config item to localconn")
	return nil
}

// LoadConfig method is responsible for loading the configuration
func (connConf *LocalConn) LoadSignConfig() error {
	jsonFile, err := os.Open("./config/signConfig.json")
	if err != nil {
		log.Errorln("fail open signConfig.json")
		return err
	}
	log.Infoln("successfully open signConfig.json")
	defer jsonFile.Close()
	// Read the contents of the file
	byteValue, _ := io.ReadAll(jsonFile)

	// Unmarshal the JSON data into the LocalConfig struct of the LocalConn instance
	tmpConf := &LocalConfig{}
	err = json.Unmarshal(byteValue, tmpConf)
	if err != nil {
		log.Errorln("fail unmarshal signConfig.json")
		return err
	}
	connConf.LocalConfig.Signers = tmpConf.Signers
	connConf.LocalConfig.MessageToSign = tmpConf.MessageToSign
	log.Infoln("done unmarshal signConfig and add new config item to localconn")
	return nil
}

// SetUpConn function is responsible for setting up the connection
func SetUpConn() LocalConn {
	// Load the connection configuration file
	var conn LocalConn
	conn.LoadConnConfig()
	// Start the server to establish connections with other parties
	conn.StartServer()

	return conn

}

// SetUpConn function is responsible for setting up the connection
func SetUpConnReshare() LocalConn {
	// Load the connection configuration file
	var conn LocalConn
	conn.LoadConnConfigReshare()
	// Start the server to establish connections with other parties
	conn.StartServer()

	return conn

}

// P2pSend function is used to send a message to a specific party in a point-to-point manner
func (connConf *LocalConn) P2pSend(toPartyID party.ID, message []byte) error {
	// Prepend the size of the message to the message data
	msgSize := IntToBytes(len(message))
	message = append(msgSize, message...)
	//Write the message to the connection associated with the specified party ID
	_, err := connConf.IDConnMap[toPartyID].Write(message)
	if err != nil {
		log.Errorf("fail send messsage to %v", toPartyID)
		return err
	}
	return nil
}

// P2pReceive function receives a message from a specific party in a point-to-point manner.
func (connConf *LocalConn) P2pReceive(fromPartyID party.ID) ([]byte, error) {

	buf := make([]byte, 1e6)
	conn := connConf.IDConnMap[fromPartyID]
	size := -1
	tmpSize := 0
	n, err := conn.Read(buf)

	var tmpMsgByte []byte
	if err != nil || n <= 4 {
		log.Errorln("fail read message")
		return nil, err
	}
	//extract the size of the message from the first 4 bytes of the buffer.
	sizeByte := buf[:4]
	size = BytesToInt(sizeByte)
	// initialize tmpMsgByte to store the received message data, excluding the size bytes.
	tmpMsgByte = buf[4:n]
	//update tmpSize to indicate the current size of the received data.
	tmpSize = n - 4
	//enter a loop to read additional data from the connection until the size of the received data reaches the expected size
	for tmpSize < size {
		//read data into a new buffer buf and appends it to tmpMsgByte
		buf := make([]byte, 1e6)
		n, err := conn.Read(buf)
		if err != nil {
			log.Errorln(err)
		}
		tmpMsgByte = append(tmpMsgByte, buf[:n]...)
		tmpSize += n
	}

	if err != nil {
		log.Errorf("fail receive messsage from %v", fromPartyID)
		return nil, err
	}
	log.Infof("receive from party %v message len is %v \n", fromPartyID, size)
	return tmpMsgByte, nil
}

// BroadcastSend function sends a message to each participant individually in a broadcast manner
func (connConf *LocalConn) BroadcastSend(message []byte) error {
	for id := range connConf.IDConnMap {
		go func(id party.ID) {
			//call the P2pSend function to send the message to the specified party.
			err := connConf.P2pSend(id, message)
			if err != nil {
				log.Errorf("fail broadcast messsage to %v", id)
				return
			}
			log.Infof("send to party %v message len is %v\n", id, len(message))
		}(id)

	}
	return nil
}

// BroadcastReceive function receives a message from each of the other participants in a broadcast manner.
func (connConf *LocalConn) BroadcastReceive() (map[party.ID][]byte, error) {
	// create a msgMap to store the received messages from other parties
	msgMap := make(map[party.ID][]byte, connConf.LocalConfig.TotalPartyCount-1)

	//initialize a mutex to control concurrent writes to the msgMap.
	var mutex sync.Mutex

	//create a WaitGroup wg to control the execution of the message receiving goroutines.
	//The number of goroutines is equal to the total number of other parties
	wg := sync.WaitGroup{}
	wg.Add(connConf.LocalConfig.TotalPartyCount - 1)

	for _, fromPartyID := range connConf.LocalConfig.OtherPartyIDs {
		go func(fromPartyID party.ID, msgMap *map[party.ID][]byte) {
			defer wg.Done()
			//call the P2pReceive function to receive the message from the specified party.
			receiveMsg, err := connConf.P2pReceive(fromPartyID)
			if err != nil {
				log.Errorf("receive from %v errror", fromPartyID)
				return
			}
			log.Infof("receive from %v msg", fromPartyID)
			//If the message is successfully received, it locks the mutex,
			mutex.Lock()
			//update the msgMap with the received message,
			(*msgMap)[fromPartyID] = receiveMsg
			// unlock the mutex.
			mutex.Unlock()
		}(fromPartyID, &msgMap)

	}
	wg.Wait()

	log.Infoln("received all broadcast messages")
	return msgMap, nil
}

// BroadcastReceive function receives a message from other new parties in a broadcast manner.
func (connConf *LocalConn) BroadcastReceiveFromNewparty() (map[party.ID][]byte, error) {
	// create a msgMap to store the received messages from other parties
	msgMap := make(map[party.ID][]byte, connConf.LocalConfig.NewPartyCount-1)

	//initialize a mutex to control concurrent writes to the msgMap.
	var mutex sync.Mutex

	//create a WaitGroup wg to control the execution of the message receiving goroutines.
	//The number of goroutines is equal to the total number of other parties
	wg := sync.WaitGroup{}
	wg.Add(connConf.LocalConfig.NewPartyCount - 1)

	for _, fromPartyID := range connConf.LocalConfig.NewPartyIDs {
		if fromPartyID == connConf.LocalConfig.LocalID {
			continue
		}
		go func(fromPartyID party.ID, msgMap *map[party.ID][]byte) {
			defer wg.Done()
			//call the P2pReceive function to receive the message from the specified party.
			receiveMsg, err := connConf.P2pReceive(fromPartyID)
			if err != nil {
				log.Errorf("receive from %v errror", fromPartyID)
				return
			}
			log.Infof("receive from %v msg", fromPartyID)
			//If the message is successfully received, it locks the mutex,
			mutex.Lock()
			//update the msgMap with the received message,
			(*msgMap)[fromPartyID] = receiveMsg
			// unlock the mutex.
			mutex.Unlock()
		}(fromPartyID, &msgMap)

	}
	wg.Wait()

	log.Infoln("received all broadcast messages from new parties")
	return msgMap, nil
}

// BroadcastReceive function receives a message from old parties in a broadcast manner.
func (connConf *LocalConn) BroadcastReceiveFromOldparty() (map[party.ID][]byte, error) {
	// create a msgMap to store the received messages from other parties
	msgMap := make(map[party.ID][]byte, connConf.LocalConfig.OldPartyCount-1)

	//initialize a mutex to control concurrent writes to the msgMap.
	var mutex sync.Mutex

	//create a WaitGroup wg to control the execution of the message receiving goroutines.
	//The number of goroutines is equal to the total number of other parties
	wg := sync.WaitGroup{}
	wg.Add(connConf.LocalConfig.OldPartyCount)

	for _, fromPartyID := range connConf.LocalConfig.OldPartyIDs {
		if fromPartyID == connConf.LocalConfig.LocalID {
			continue
		}
		go func(fromPartyID party.ID, msgMap *map[party.ID][]byte) {
			defer wg.Done()
			//call the P2pReceive function to receive the message from the specified party.
			receiveMsg, err := connConf.P2pReceive(fromPartyID)
			if err != nil {
				log.Errorf("receive from %v errror", fromPartyID)
				return
			}
			log.Infof("receive from %v msg", fromPartyID)
			//If the message is successfully received, it locks the mutex,
			mutex.Lock()
			//update the msgMap with the received message,
			(*msgMap)[fromPartyID] = receiveMsg
			// unlock the mutex.
			mutex.Unlock()
		}(fromPartyID, &msgMap)

	}
	wg.Wait()

	log.Infoln("received all broadcast messages from old parties")
	return msgMap, nil
}

// IntToBytes function converts an integer to a byte slice
func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

// BytesToInt converts a byte slice to an integer.
func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)

	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)

	return int(x)
}
