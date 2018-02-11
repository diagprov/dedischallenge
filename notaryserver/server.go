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

	signature, err := schnorrgs.SchnorrSignBinary(suite, *kv, buffer)

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
		fmt.Printf(err.Error())
		exitCh <- struct{}{}
		return
	}
	sock, err := net.ListenTCP("tcp", addr)
	if err != nil {
		// error
		fmt.Printf(err.Error())
		exitCh <- struct{}{}
		return
	}
	// Let Accept be non-blocking / fall through to our loop
	// an alternative would be for accept to dispatch as needed
	// via a select / goroutines and then
	// each handler function could check whether it should handle or exit.
	for {
		sock.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Println("Accepting connections")
		conn, err := sock.Accept()
		fmt.Println("Accept Done")
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
			} else {
				fmt.Println(err.Error())
				fmt.Println(err.Error())
				exitCh <- struct{}{}
				return
			}
		} else {
			fmt.Println("Got something to handle, dispatching")
			go handler(conn)
			time.Sleep(250 * time.Millisecond)
		}
		// check if we need to exit:
		fmt.Println("Checking exit status")
		checkctx, _ := context.WithDeadline(ctx, time.Now().Add(100*time.Millisecond))
		select {
		case <-checkctx.Done():
			exitCh <- struct{}{}
			return
		default:
		}
	}
}
