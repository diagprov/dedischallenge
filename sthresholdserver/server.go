
package main

import (
    "fmt"
    "net"
    "bytes"
    "io"
    "github.com/dedis/crypto/abstract"
    "vennard.ch/crypto"
)

type connectionhandler func(conn net.Conn)

type State byte

const (
        INIT    byte = 0
        MESSAGE byte = 1
        COMMITMENT byte = 2
)

func signOneKBMSchnorr(conn net.Conn, suite abstract.Suite, kv crypto.SchnorrKeyset) {

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
        _,err := conn.Read(buffer)
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
    var aggregateCommitment crypto.SchnorrMAggregateCommmitment
    var privateCommit crypto.SchnorrMPrivateCommitment

    for {
        select {
        case data := <-ch:
            
            // validate state transition - we can only 
            // transfer to the next state in the protocol
            // anything else and we simply ignore the message
            // eventually we time out and close the connection
            newState := data[0]

            fmt.Println("SERVER", "Selected data channel, states are", newState, internalState)
            if newState != (internalState+1) {
                continue
            }
            internalState = newState

            payload := data[2:]

            switch newState {
            case MESSAGE:

                fmt.Println("SERVER", "Received Message")

                message = payload

                privateCommitment, err := crypto.SchnorrMGenerateCommitment(suite)
                if err != nil {
                    fmt.Println("Error generating commitment")
                    fmt.Println(err.Error())
                    break
                }
                privateCommit = privateCommitment

                publicCommitment := privateCommitment.PublicCommitment()

                buf := bytes.Buffer{} 
                abstract.Write(&buf, &publicCommitment, suite)
                conn.Write(buf.Bytes())

            case COMMITMENT:


                fmt.Println("SERVER", "Received Commitment")
                

                buf := bytes.NewBuffer(payload)
                err := abstract.Read(buf, &aggregateCommitment, suite);
                if err != nil {
                    fmt.Println("Error binary decode of aggregateCommitment")
                    fmt.Println(err.Error())
                    break
                }

                collectiveChallenge := crypto.SchnorrMComputeCollectiveChallenge(suite,message,aggregateCommitment)
                response := crypto.SchnorrMUnmarshallCCComputeResponse(suite, kv, privateCommit, collectiveChallenge)

                outBuf := bytes.Buffer{} 
                abstract.Write(&outBuf, &response, suite)
                conn.Write(outBuf.Bytes())

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
  


func serve(port int, handler connectionhandler) {
    
    if port < 1024 || port > 65535 {
        // todo: how does go handle errors.
    }

    portspec := fmt.Sprintf(":%d", port)

    sock, err := net.Listen("tcp", portspec)
    if err != nil {
        // error
        fmt.Printf("%d", err)
    }

    for {
        conn, err := sock.Accept()
        if err != nil {
            fmt.Printf("%d", err)     
        }
        go handler(conn) 
    }
}
