package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/diagprov/dedischallenge/schnorrgs"
	"net"
)

func main() {
	var port int
	var hostname string
	var kfilepath string

	flag.StringVar(&kfilepath, "keyfile", "", "Use the keyfile specified")
	flag.StringVar(&hostname, "host", "localhost", "Connect to the specified host")
	flag.IntVar(&port, "port", 1111, "Use the specified port")
	flag.Parse()

	suite := edwards25519.NewBlakeSHA256Ed25519()

	pk, err := schnorrgs.SchnorrLoadPubkey(kfilepath)
	if err != nil {
		fmt.Println("Error " + err.Error())
		return
	}

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

	sig, err := schnorrgs.DecodeSchnorrSignature(suite, buffer)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	v, err := schnorrgs.SchnorrVerify(suite, *pk, randomdata, sig)
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
