package main

import (
	"flag"
	"fmt"
	"github.com/dedis/kyber/edwards/ed25519"
	"github.com/diagprov/dedischallenge/schnorrgs"
	"golang.org/x/net/context"
	"net"
	"os"
	"os/signal"
)

func main() {
	var port int
	var kfilepath string

	flag.IntVar(&port, "port", 1111, "Listen on given port")
	flag.StringVar(&kfilepath, "keyfile", "", "Use the keyfile specified")

	flag.Parse()
	fmt.Printf("notary - listening on port %d.\n", port)

	suite := ed25519.NewAES128SHA256Ed25519(true)
	kv, err := schnorrgs.SchnorrLoadKeypair()
	if err != nil {
		fmt.Println("Error " + err.Error())
		return
	}


	// I don't know if there's a way to
	// do std::bind-like behaviour in GO.
	// for C++ what I'd do is pretty simple:
	// newfunc := std::bind(&func, args to bind)
	var signOneKBImpl connectionhandler = func(conn net.Conn) {
		signOneKBSchnorr(conn, suite, kv)
	}

    ctx, cancel := context.WithCancel(context.Background())

	serve(port, signOneKBImpl, ctx)

    signalCh := make(chan os.Signal, 1)
    signal.Notify(signalCh, os.Interrupt)

    go func() { 
        select {
        case <- signalCh:
            cancel()
            return
        }
    }()
    <-

}
