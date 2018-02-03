
package main

import (
	"fmt"
	"os"
	"encoding/json"
	"github.com/dedis/crypto/edwards/ed25519"
	"vennard.ch/crypto"
)

type SchnorrMSHostSpec struct {
	HostName    string
	Port        int
	KeyFilePath string
}

type SchnorrMMember struct {
	HostName    string
	Port        int
	PKey        crypto.SchnorrPublicKey
}

type SchnorrMGroupConfig struct {
	JointKey    crypto.SchnorrPublicKey
	Members     []SchnorrMMember
}

/* Create a group configuration file. This is really a convenience feature 
   more than anything, making it easier to direct the client than supplying 
   all the arguments on the command line. */
func runMultiSignatureGen (group []SchnorrMSHostSpec, outputFile string) error {

	var config SchnorrMGroupConfig
	var pkeys []crypto.SchnorrPublicKey

	suite := ed25519.NewAES128SHA256Ed25519(true) 
	for _, mshp :=  range group {

		pkey, err := crypto.SchnorrLoadPubkey(mshp.KeyFilePath, suite)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		pkeys = append(pkeys, pkey)

		member := SchnorrMMember{mshp.HostName, mshp.Port, pkey}
		config.Members = append(config.Members, member)
	}

	jointKey := crypto.SchnorrMComputeSharedPublicKey(suite, pkeys)
	config.JointKey = jointKey.GetSchnorrPK()

    data, _ := json.Marshal(config)


    f, err := os.OpenFile(outputFile, os.O_CREATE | os.O_RDWR, 0644)
    if err != nil { return err }
    defer f.Close()
    _, err = f.Write(data)
	return err
}