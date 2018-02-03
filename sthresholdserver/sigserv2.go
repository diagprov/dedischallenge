
package main

import (
    "fmt"
    "net"
    "flag"
	"github.com/dedis/crypto/edwards/ed25519"
	"vennard.ch/crypto"
)

func main() {
	var port int
	var kfilepath string

	flag.IntVar(&port, "port", 1111, "Listen on given port")
	flag.StringVar(&kfilepath, "keyfile", "", "Use the keyfile specified")

	flag.Parse()
    fmt.Printf("Sigserv1 - listening on port %d.\n", port)

    suite := ed25519.NewAES128SHA256Ed25519(true) 
    kv, err := crypto.SchnorrLoadKeypair(kfilepath, suite)
    if err != nil {
    	fmt.Println("Error " + err.Error())
    	return
    }

    // I don't know if there's a way to 
    // do std::bind-like behaviour in GO.
    // for C++ what I'd do is pretty simple: 
    // newfunc := std::bind(&func, args to bind)
    var signOneKBImpl connectionhandler = func(conn net.Conn) {
        signOneKBMSchnorr(conn, suite, kv)
    }
    serve(port, signOneKBImpl)
}
