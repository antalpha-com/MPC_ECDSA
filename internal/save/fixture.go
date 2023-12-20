// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package save

import (
	"MPC_ECDSA/pkg/ecdsa"
	"MPC_ECDSA/pkg/ecdsa3rounds"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/protocols"
	"MPC_ECDSA/protocols/config"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	log "github.com/sirupsen/logrus"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	LocalKeygenFixtureDirFormat  = "%s/../../test/local_test_fixture/local_keygen"
	localKeygenFixtureFileFormat = "keygen_result_%s.data"
	keygenFixtureDirFormat       = "%s/../../test/keygen_fixture"
	keygenFixtureFileFormat      = "keygen_result.data"
	reshareFixtureDirFormat      = "%s/../../test/reshare_fixture"
	reshareFixtureFileFormat     = "reshare_result.data"
	presign3FixtureDirFormat     = "%s/../../test/presign3_fixture"
	presign3FixtureFileFormat    = "presign3_result_%s.data"
	presign6FixtureDirFormat     = "%s/../../test/presign6_fixture"
	presign6FixtureFileFormat    = "presign6_result_%s.data"
)

func makeTestFixtureFilePath(dirFormat, fileFormat, stage string, index string) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(dirFormat, srcDirName)
	println(fmt.Sprintf("%s/"+fileFormat, fixtureDirName, index))
	var filePath string
	switch stage {
	case "keygen":
		filePath = filepath.Clean(fmt.Sprintf("%s/"+fileFormat, fixtureDirName))
		break
	case "reshare":
		filePath = filepath.Clean(fmt.Sprintf("%s/"+fileFormat, fixtureDirName))
		break
	case "presign3":
		filePath = filepath.Clean(fmt.Sprintf("%s/"+fileFormat, fixtureDirName, index))
		break
	case "presign6":
		filePath = filepath.Clean(fmt.Sprintf("%s/"+fileFormat, fixtureDirName, index))
		break
	case "testStage":
		filePath = filepath.Clean(fmt.Sprintf("%s/"+fileFormat, fixtureDirName))
		break
	case "localKeygen":
		filePath = filepath.Clean(fmt.Sprintf("%s/"+fileFormat, fixtureDirName, index))
		break
	}
	return filePath
}

// makeFilePathWithEntryName make file path with entry name
func makeFilePathWithEntryName(dirFormat, entryName string) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	dirName := fmt.Sprintf(dirFormat, srcDirName)
	filePath := dirName + "/" + entryName
	return filePath
}

// SaveLocalKeyGenResult saves the keygen configuration to a file
func SaveLocalKeyGenResult(config *protocols.Config, index string) error {
	//marshal the configuration
	//marshalledConfig, err := config.MarshalBinary()
	marshalledConfig, err := cbor.Marshal(config)
	if err != nil {
		return err
	}
	//write the configuration to a file
	err = WriteFixtureFile(marshalledConfig, "localKeygen", index, LocalKeygenFixtureDirFormat, localKeygenFixtureFileFormat)
	if err != nil {
		return err
	}
	return nil
}

func turnIntoInterface(c interface{}) interface{} {
	return c
}

// LoadLocalKeyGenResults loads the keygen configuration from files under LocalKeygenFixtureDirFormat dir
func LoadLocalKeyGenResults() (map[party.ID]interface{}, error) {
	//read the configuration from a file
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	directoryPath := fmt.Sprintf(LocalKeygenFixtureDirFormat, srcDirName)
	entries, err := os.ReadDir(directoryPath)
	if err != nil {
		return nil, err
	}
	configs := make(map[party.ID]interface{})
	for _, entry := range entries {
		index := GetIDWithEntryName(entry.Name())
		fileResult, err := ReadFixtureFile("localKeygen", index, LocalKeygenFixtureDirFormat, localKeygenFixtureFileFormat)
		if err != nil {
			return nil, err
		}
		//unmarshal the configuration
		conf := config.EmptyConfig(curve.Secp256k1{})
		err = cbor.Unmarshal(fileResult, &conf)
		if err != nil {
			return nil, err
		}
		configs[conf.ID] = turnIntoInterface(conf)
	}
	return configs, nil
}
func LoadKeyGenResult2() (interface{}, error) {
	//read the configuration from a file
	fileResult, err := ReadFixtureFile("keygen", "", keygenFixtureDirFormat, keygenFixtureFileFormat)
	if err != nil {
		return nil, err
	}
	//unmarshal the configuration
	config := config.EmptyConfig(curve.Secp256k1{})
	err = cbor.Unmarshal(fileResult, &config)
	if err != nil {
		return nil, err
	}
	var configInterface interface{}
	configInterface = turnIntoInterface(config)
	return configInterface, nil
}

// LoadLocalKeyGenResultWithID loads the keygen configuration from a file
func LoadLocalKeyGenResultWithID(id party.ID) (*protocols.Config, error) {
	//read the configuration from a file
	fileResult, err := ReadFixtureFile("localKeygen", string(id), LocalKeygenFixtureDirFormat, localKeygenFixtureFileFormat)
	if err != nil {
		return nil, err
	}
	//unmarshal the configuration
	config := config.EmptyConfig(curve.Secp256k1{})
	err = cbor.Unmarshal(fileResult, &config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// SaveKeyGenResult saves the keygen configuration to a file
func SaveKeyGenResult(config *protocols.Config) error {
	//marshal the configuration
	//marshalledConfig, err := config.MarshalBinary()
	marshalledConfig, err := cbor.Marshal(config)
	if err != nil {
		return err
	}
	//write the configuration to a file
	err = WriteFixtureFile(marshalledConfig, "keygen", "", keygenFixtureDirFormat, keygenFixtureFileFormat)
	if err != nil {
		return err
	}
	return nil
}

// SaveKeyGenResult saves the keygen configuration to a file
func SaveReshareResult(config *protocols.Config) error {
	//marshal the configuration
	//marshalledConfig, err := config.MarshalBinary()
	marshalledConfig, err := cbor.Marshal(config)
	if err != nil {
		return err
	}
	//write the configuration to a file
	err = WriteFixtureFile(marshalledConfig, "reshare", "", reshareFixtureDirFormat, reshareFixtureFileFormat)
	if err != nil {
		return err
	}
	return nil
}

// LoadKeyGenConfig loads the keygen configuration from a file
func LoadReshareResult() (*protocols.Config, error) {
	//read the configuration from a file
	fileResult, err := ReadFixtureFile("keygen", "", reshareFixtureDirFormat, reshareFixtureFileFormat)
	if err != nil {
		return nil, err
	}
	//unmarshal the configuration
	config := config.EmptyConfig(curve.Secp256k1{})
	err = cbor.Unmarshal(fileResult, &config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// LoadKeyGenConfig loads the keygen configuration from a file
func LoadKeyGenResult() (*protocols.Config, error) {
	//read the configuration from a file
	fileResult, err := ReadFixtureFile("keygen", "", keygenFixtureDirFormat, keygenFixtureFileFormat)
	if err != nil {
		return nil, err
	}
	//unmarshal the configuration
	config := config.EmptyConfig(curve.Secp256k1{})
	err = cbor.Unmarshal(fileResult, &config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// LoadKeyGenConfig loads the keygen configuration from a file

// SavePresign3Result saves the presign3 result to a file
func SavePresign3Result(result *ecdsa3rounds.PreSignature3, presignIndex string) error {
	// marshal the result
	marshalledResult, err := cbor.Marshal(result)
	if err != nil {
		log.Errorf("fail to marshal presign3 result , err is %v", err)
		return err
	}
	// write the result to a file
	err = WriteFixtureFile(marshalledResult, "presign3", presignIndex, presign3FixtureDirFormat, presign3FixtureFileFormat)
	if err != nil {
		return err
	}
	return nil
}

// LoadPresign3Result loads the presign3 result from a file
func LoadPresign3Result(presignIndex string) (*ecdsa3rounds.PreSignature3, error) {
	// read the result from a file
	fileResult, err := ReadFixtureFile("presign3", presignIndex, presign3FixtureDirFormat, presign3FixtureFileFormat)
	if err != nil {
		return nil, err
	}
	// unmarshal the result
	result := ecdsa3rounds.EmptyPreSignature(curve.Secp256k1{})
	err = cbor.Unmarshal(fileResult, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// SavePresign6Result saves the presign6 result to a file
func SavePresign6Result(result *ecdsa.PreSignature, presignIndex string) error {
	// marshal the result
	marshalledResult, err := cbor.Marshal(result)
	if err != nil {
		log.Errorf("fail to marshal presign3 result , err is %v", err)
		return err
	}
	// write the result to a file
	err = WriteFixtureFile(marshalledResult, "presign6", presignIndex, presign6FixtureDirFormat, presign6FixtureFileFormat)
	if err != nil {
		return err
	}
	return nil
}

// LoadPresign6Result loads the presign3 result from a file
func LoadPresign6Result(presignIndex string) (*ecdsa.PreSignature, error) {
	// read the result from a file
	fileResult, err := ReadFixtureFile("presign6", presignIndex, presign6FixtureDirFormat, presign6FixtureFileFormat)
	if err != nil {
		return nil, err
	}
	// unmarshal the result
	result := ecdsa.EmptyPreSignature(curve.Secp256k1{})
	err = cbor.Unmarshal(fileResult, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// deletePreSign3Result deletes the presign3 result from a file
func DeletePreSign3Result(presignIndex string) error {
	err := DeleteFixtureFile("presign3", presignIndex, presign3FixtureDirFormat, presign3FixtureFileFormat)
	if err != nil {
		return err
	}
	return nil
}

// deletePreSign6Result deletes the presign3 result from a file
func DeletePreSign6Result(presignIndex string) error {
	err := DeleteFixtureFile("presign6", presignIndex, presign6FixtureDirFormat, presign6FixtureFileFormat)
	if err != nil {
		return err
	}
	return nil
}

// WriteFixtureFile saves the []byte type result to a file
// keygenResult: result(keygen or presign) to save
// returns: error if any
func WriteFixtureFile(result []byte, stage string, index string, dirFormat string, fileFormat string) error {
	fixtureFileName := makeTestFixtureFilePath(dirFormat, fileFormat, stage, index)
	err := os.MkdirAll(path.Dir(fixtureFileName), 0755)
	if err != nil {
		log.Errorln(err)
	}
	// if stage is presign3 or presign6, then we need to see file exists or not
	if stage == "presign3" || stage == "presign6" {
		_, err := os.Stat(fixtureFileName)
		if err == nil {
			log.Errorf("presignIndex %v already exists, will not overwrite file, please input another presign id", index)
			return err
		}
	}
	// open file
	fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Errorf("unable to open save file %s for writing", fixtureFileName)
		return err
	}

	// write json to file
	_, err = fd.Write(result)
	if err != nil {
		log.Errorf("unable to write json to save file %s", fixtureFileName)
		return err
	}
	// close file
	err = fd.Close()
	if err != nil {
		log.Errorf("unable to close save file %s", fixtureFileName)
		return err
	}
	log.Infof("done wrote save file %s", fixtureFileName)

	return nil
}

// ReadFixtureFile reads the keygen result from a json file
// and returns the result as a byte array and the number of bytes read
// returns: []byte, int, error
func ReadFixtureFile(stage string, index string, dirFormat string, fileFormat string) ([]byte, error) {
	fixtureFileName := makeTestFixtureFilePath(dirFormat, fileFormat, stage, index)
	// open file
	fd, err := os.Open(fixtureFileName)
	if err != nil {
		log.Errorf("unable to open save file %s for reading", fixtureFileName)
		return nil, err
	}
	// read file
	jsonResult := make([]byte, 16384)
	_, err = fd.Read(jsonResult)
	if err != nil {
		log.Errorf("unable to read save file %s", fixtureFileName)
		return nil, err
	}
	// close file
	err = fd.Close()
	if err != nil {
		log.Errorf("unable to close save file %s", fixtureFileName)
		return nil, err
	}
	log.Infof("done read save file %s", fixtureFileName)
	return jsonResult, nil
}

// delete fixture file
func DeleteFixtureFile(stage string, index string, dirFormat string, fileFormat string) error {
	fixtureFileName := makeTestFixtureFilePath(dirFormat, fileFormat, stage, index)
	err := os.Remove(fixtureFileName)
	if err != nil {
		log.Errorf("unable to delete fixture file %s", fixtureFileName)
		return err
	}
	log.Infof("done delete fixture file %s", fixtureFileName)
	return nil
}

// clear all files dir contains
func ClearFixtureFiles(dir string) error {
	entries, err := os.ReadDir(dir)

	if err != nil {
		return err
	}
	for _, entry := range entries {
		entryPath := makeFilePathWithEntryName(dir, entry.Name())
		err := os.Remove(entryPath)
		if err != nil {
			return err
		}
	}
	return nil
}

// getIDWithEntryName split entry name by '_', and get the last part as id and return
func GetIDWithEntryName(entryName string) string {
	// split string with '_'
	split := strings.Split(entryName, "_")
	// split[len(split)-1] split with '.'
	split = strings.Split(split[len(split)-1], ".")
	return split[0]
}
