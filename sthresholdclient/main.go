package main

import (
	//    "crypto/rand"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	"os"
	//    "github.com/dedis/crypto/edwards/ed25519"
	//    "vennard.ch/crypto"
)

// because kingpin worked so nicely in the keytool, let's use it again:

var (
	app        = kingpin.New("sthresholdclient", "Command line client for multisignature schnorr")
	configFile = app.Arg("config", "Read the group configuration from this file").Required().String()
)

func main() {
	kingpin.MustParse(app.Parse(os.Args[1:]))

	runClientProtocol(*configFile)
}
