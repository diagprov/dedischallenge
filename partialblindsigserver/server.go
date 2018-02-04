package main

import (
	"bytes"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"golang.org/x/net/context"
	"io"
	"net"
	"time"
)

// type alias for handling connections.
type connectionhandler func(conn net.Conn)

/* This function implements the signer protocol from the blind signature paper
   and can be bound via closure given a specific set of parameters and
   send to the serve() function
   This is not the best accept() handler ever written,  but it's better than the client side code */
func signBlindlySchnorr(conn net.Conn,
	suite abstract.Suite,
	kv crypto.SchnorrKeyset,
	sharedinfo []byte) {
	defer conn.Close()

	fmt.Println("SERVER", "Sending initial parameters")

	signerParams, err := crypto.NewPrivateParams(suite, sharedinfo)
	if err != nil {
		fmt.Println("SERVER", "Error creating new private parameters", err.Error())
		return
	}

	// "send" these to the user.
	userPublicParams := signerParams.DerivePubParams()
	buffer := bytes.Buffer{}
	abstract.Write(&buffer, &userPublicParams, suite)
	conn.Write(buffer.Bytes())

	// now we need to wait for the client to send us "e"
	ch := make(chan []byte)
	errorCh := make(chan error)

	// this neat little routine for wrapping read connections
	// in a class unashamedly stolen from stackoverflow:
	// http://stackoverflow.com/a/9764191
	go func(ch chan []byte, eCh chan error) {
		for {
			// try to read the data
			fmt.Println("SERVER", "Read goroutine off and going")
			buffer := make([]byte, 1026)
			_, err := conn.Read(buffer)
			if err != nil {
				// send an error if it's encountered
				errorCh <- err
				return
			}
			// send data if we read some.
			ch <- buffer
		}
	}(ch, errorCh)

	for {
		select {
		case data := <-ch:
			fmt.Println("SERVER", "Received Message")

			var challenge crypto.WISchnorrChallengeMessage
			buffer := bytes.NewBuffer(data)
			err = abstract.Read(buffer, &challenge, suite)
			if err != nil {
				fmt.Println("SERVER", "Error", err.Error())
				return
			}

			response := crypto.ServerGenerateResponse(suite, challenge, signerParams, kv)
			respbuffer := bytes.Buffer{}
			abstract.Write(&respbuffer, &response, suite)
			conn.Write(respbuffer.Bytes())

			fmt.Println("SERVER", "We're done")
			return

		case err := <-errorCh:
			if err == io.EOF {
				return
			}
			// we should, really, log instead.
			fmt.Println("Encountered error serving client")
			fmt.Println(err.Error())
			break
		}
	}

}

/* The serve function is designed to serve an arbitrary connection handler
   specified as a handler of type connectionhandler on port "port"
   from this machine.
*/
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
