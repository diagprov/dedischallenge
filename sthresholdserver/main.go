package main

import (
	"flag"
	"fmt"
	"github.com/dedis/kyber/group/edwards25519"
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
	fmt.Printf("sthresholdserver - listening on port %d.\n", port)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	kv, err := schnorrgs.SchnorrLoadSecretKV(kfilepath)
	if err != nil {
		fmt.Println("Error " + err.Error())
		return
	}

	exitCh := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())

	var signOneKBImpl connectionhandler = func(conn net.Conn) {
		signOneKBMSchnorr(conn, suite, *kv)
	}
	serve(port, signOneKBImpl, ctx, exitCh)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)

	go func() {
		select {
		case <-signalCh:
			cancel()
			return
		}
	}()

	// delay main thread until worker has returned.
	<-exitCh

}
