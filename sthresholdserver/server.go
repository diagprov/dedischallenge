package main

import (
	"fmt"
	"github.com/diagprov/dedischallenge/schnorrgs"
	"golang.org/x/net/context"
	"io"
	"net"
	"time"
)

type connectionhandler func(conn net.Conn)

type State byte

const (
	INIT       byte = 0
	MESSAGE    byte = 1
	COMMITMENT byte = 2
)

func signOneKBMSchnorr(conn net.Conn, suite schnorrgs.CryptoSuite, kv schnorrgs.SchnorrSecretKV) {

	defer conn.Close()

	fmt.Println(suite)

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

	var internalState byte = INIT
	var message []byte
	var aggregateCommitment schnorrgs.SchnorrMSPublicCommitment
	var privateCommitment schnorrgs.SchnorrMSCommitment

	for {
		select {
		case data := <-ch:

			// validate state transition - we can only
			// transfer to the next state in the protocol
			// anything else and we simply ignore the message
			// eventually we time out and close the connection
			newState := data[0]

			fmt.Println("SERVER", "Selected data channel, states are", newState, internalState)
			if newState != (internalState + 1) {
				continue
			}
			internalState = newState

			payload := data[2:]

			switch newState {
			case MESSAGE:

				fmt.Println("SERVER", "Received Message")

				message = payload

				privateCommitment := schnorrgs.SchnorrMSGenerateCommitment(suite)

				publicCommitment := privateCommitment.GetPublicCommitment()

				b, err := publicCommitment.MarshalBinary()
				if err != nil {
					fmt.Println("Error")
					fmt.Println(err.Error)
					return
				}

				conn.Write(b)

			case COMMITMENT:

				fmt.Println("SERVER", "Received Commitment")

				err := aggregateCommitment.UnmarshalBinary(suite, payload)
				if err != nil {
					fmt.Println("Error")
					fmt.Println(err.Error)
					return
				}
				collectiveChallenge, err := schnorrgs.SchnorrMSComputeCollectiveChallenge(suite, aggregateCommitment, message)
				if err != nil {
					fmt.Println("Error")
					fmt.Println(err.Error)
					return
				}
				response := schnorrgs.SchnorrMSComputeResponse(suite, collectiveChallenge, kv, privateCommitment)
				b, err := response.MarshalBinary()
				if err != nil {
					fmt.Println("Error")
					fmt.Println(err.Error)
					return
				}
				conn.Write(b)

				// we're now at the end, we can break and close connection
				break
			default:
				fmt.Println("Didn't understand message, received:")
				fmt.Println(data)
			}

		case err := <-errorCh:
			if err == io.EOF {
				return
			}
			// we should, really, log instead.
			fmt.Println("Encountered error serving client")
			fmt.Println(err.Error())
			break

			// well, the *idea* was to have this but frustratingly
			// it does not compile.  Oh well.
			//case time.Tick(time.Minute):
			// more robust handling of connections.
			// don't allow clients to hold the server open
			// indefinitely.
			//break
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
