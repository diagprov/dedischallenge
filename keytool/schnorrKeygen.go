

package main

import (
    "fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards/ed25519"
	"vennard.ch/crypto"
)

/* Does excactly what it sounds like - creates and saves a schnorr public/private keypair.
   Much like ssh-keygen, we append .pub to the public key. Unlike ssh-keygen we append .pri 
   to the private key also. */
func runKeyGen(kpath string) {
	suite := ed25519.NewAES128SHA256Ed25519(true) 
	KeyGen(suite, kpath)
}

/* abstract keygen function. Takes any suite, although later code assumes ED25519 with the 
   fill curve group */
func KeyGen(suite abstract.Suite,
			kpath string) {

	var kpubpath string = kpath
	var kpripath string = kpath
	kpubpath = kpubpath + ".pub"
	kpripath = kpripath + ".pri"

	keypair, err := crypto.SchnorrGenerateKeypair(suite)
	if err != nil {
		fmt.Println("Key generation failed")
		return
	}
	pubkey := crypto.SchnorrExtractPubkey(keypair)

	r := crypto.SchnorrSaveKeypair(kpripath, suite, keypair)
	if r != nil {
		fmt.Printf("Unable to write to %s\n", kpripath)
		fmt.Println("Error is")
		fmt.Println(r.Error())
		return
	}
	r = crypto.SchnorrSavePubkey(kpubpath, suite, pubkey)
	if r != nil {
		fmt.Printf("Unable to write to %s\n", kpubpath)
		return
	}
	fmt.Println("Written private keypair to : " + kpripath)
	fmt.Println("Written public key to      : " + kpubpath)
}