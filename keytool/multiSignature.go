package main

import (
	"encoding/json"
	"fmt"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/diagprov/dedischallenge/schnorrgs"
	"os"
)

type SchnorrMSHostSpec struct {
	HostName    string
	Port        int
	KeyFilePath string
}

type SchnorrMMember struct {
	HostName string
	Port     int
	PKey     string
}

type SchnorrMGroupConfig struct {
	JointKey string
	Members  []SchnorrMMember
}

/* Create a group configuration file. This is really a convenience feature
   more than anything, making it easier to direct the client than supplying
   all the arguments on the command line. */
func runMultiSignatureGen(group []SchnorrMSHostSpec, outputFile string) error {

	var config SchnorrMGroupConfig
	var pkeys []schnorrgs.SchnorrPublicKV
	var pkeys_s []string

	suite := edwards25519.NewBlakeSHA256Ed25519()
	for _, mshp := range group {

		fmt.Println("Loading public key " + mshp.KeyFilePath)
		pkey, err := schnorrgs.SchnorrLoadPubkey(mshp.KeyFilePath)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		pkey_s := pkey.Export()
		pkeys = append(pkeys, *pkey)
		pkeys_s = append(pkeys_s, pkey_s)

		member := SchnorrMMember{mshp.HostName, mshp.Port, pkey_s}
		config.Members = append(config.Members, member)
	}

	jointKey := schnorrgs.SchnorrMSComputeSharedPublicKey(suite, pkeys)
	jointKey_s := jointKey.Export()
	config.JointKey = jointKey_s

	data, _ := json.Marshal(config)

	f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
