package main

import (
	"fmt"
	"github.com/diagprov/dedischallenge/schnorrgs"
	"golang.org/x/net/context"
	"net"
	"os"
	"time"
)

type connectionhandler func(conn net.Conn)

func signOneKBSchnorr(conn net.Conn, suite schnorrgs.CryptoSuite, kv *schnorrgs.SchnorrSecretKV) {
	buffer := make([]byte, 1024)

	defer conn.Close()

	bytesRead, err := conn.Read(buffer)
	if err != nil {
		fmt.Printf("%d\n", err)
	}

	if bytesRead != 1024 {
		conn.Close()
	}

	signature, err := schnorrgs.SchnorrSign(suite, *kv, buffer)

	conn.Write(signature)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	fmt.Println("Signed and responded to message.")
	conn.Close()
}

func serve(port int, handler connectionhandler, ctx context.Context, exitCh chan struct{}) {

	if port < 1024 || port > 65535 {
		// todo: how does go handle errors.
		exitCh <- struct{}{}
		return
	}

	portspec := fmt.Sprintf("0.0.0.0:%d", port)
	addr, err := net.ResolveTCPAddr("tcp", portspec)
	if err != nil {
		fmt.Printf("%d", err)
		exitCh <- struct{}{}
		return
	}
	sock, err := net.ListenTCP("tcp", addr)
	if err != nil {
		// error
		fmt.Printf("%d", err)
		exitCh <- struct{}{}
		return
	}
	// Let Accept be non-blocking / fall through to our loop
	// an alternative would be for accept to dispatch as needed
	// via a select / goroutines and then
	// each handler function could check whether it should handle or exit.
	sock.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		conn, err := sock.Accept()
		if err != nil {
			fmt.Printf("%d", err)
		} else {
			go handler(conn)
			time.Sleep(250 * time.Millisecond)
		}
		// check if we need to exit:
		select {
		case <-ctx.Done():
			exitCh <- struct{}{}
			return
		default:
		}
	}
}
