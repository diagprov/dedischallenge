package main

import (
	"fmt"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/diagprov/dedischallenge/schnorrgs"
)

/* Does excactly what it sounds like - creates and saves a schnorr public/private keypair.
   Much like ssh-keygen, we append .pub to the public key. Unlike ssh-keygen we append .pri
   to the private key also. */
func runKeyGen(kpath string) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	KeyGen(suite, kpath)
}

/* abstract keygen function. Takes any suite, although later code assumes ED25519 with the
   fill curve group */
func KeyGen(suite schnorrgs.CryptoSuite,
	kpath string) {

	var kpubpath string = kpath
	var kpripath string = kpath
	kpubpath = kpubpath + ".pub"
	kpripath = kpripath + ".pri"

	keypair, err := schnorrgs.SchnorrGenerateKeypair(suite)
	if err != nil {
		fmt.Println("Key generation failed")
		return
	}
	pubkey := keypair.GetPublicKeyset()

	r := schnorrgs.SchnorrSaveSecretKV(kpripath, keypair)
	if r != nil {
		fmt.Printf("Unable to write to %s\n", kpripath)
		fmt.Println("Error is")
		fmt.Println(r.Error())
		return
	}
	r = schnorrgs.SchnorrSavePubkey(kpubpath, pubkey)
	if r != nil {
		fmt.Printf("Unable to write to %s\n", kpubpath)
		return
	}
	fmt.Println("Written private keypair to : " + kpripath)
	fmt.Println("Written public key to      : " + kpubpath)
}
