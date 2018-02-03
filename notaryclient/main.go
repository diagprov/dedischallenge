package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"github.com/dedis/crypto/edwards/ed25519"
	"github.com/diagprov/dedischallenge/schnorrgs"
)

func main() {
	var port int
	var hostname string
	var kfilepath string

	flag.StringVar(&kfilepath, "keyfile", "", "Use the keyfile specified")
	flag.StringVar(&hostname, "host", "localhost", "Connect to the specified host")
	flag.IntVar(&port, "port", 1111, "Use the specified port")
	flag.Parse()

	suite := ed25519.NewAES128SHA256Ed25519(true)

	var pk schnorrgs.SchnorrPublicKV

	pk, err := crypto.SchnorrLoadPubkey(kfilepath, suite)
	if err != nil {
		fmt.Println("Error " + err.Error())
		return
	}

	fmt.Println("Using public key: " pk.)

	var hostspec string
	hostspec = fmt.Sprintf("%s:%d", hostname, port)
	fmt.Println("Connecting to %s\n", hostspec)
	conn, err := net.Dial("tcp", hostspec)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	randomdata := make([]byte, 1024)
	_, err = rand.Read(randomdata)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	buffer := make([]byte, 64)

	conn.Write(randomdata)
	_, err = conn.Read(buffer)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	v, err := crypto.SchnorrVerify(suite, pk, randomdata, buffer)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	if v == true {
		fmt.Println("Signature verified OK")
	} else {
		fmt.Println("Signature verify FAILED")
	}

	return
}
