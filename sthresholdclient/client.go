
package main

import (
    "bytes"
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"os"
    "net"
	"fmt"
    "github.com/dedis/crypto/abstract"
    "github.com/dedis/crypto/edwards/ed25519"
	"vennard.ch/crypto"
)

type SchnorrMMember struct {
	HostName    string
	Port        int
	PKey        crypto.SchnorrPublicKey
}

type SchnorrMGroupConfig struct {
	JointKey    crypto.SchnorrPublicKey
	Members     []SchnorrMMember
}


const (
        MESSAGE byte = 1
        COMMITMENT byte = 2
)

type controllerMessage struct {
    MemberIndex   int
    Message       [] byte    // if we don't keep this generic type enforcement 
                             // will stop us using a single channel.
}

func serverComms (gconfig SchnorrMGroupConfig, i int, msg []byte, reportChan chan controllerMessage, syncChan chan []byte) {

    config := gconfig.Members[i]

	firstMessage := []byte{MESSAGE, 0}
	firstMessage = append(firstMessage, msg...)

	hostspec := fmt.Sprintf("%s:%d", config.HostName, config.Port)

    fmt.Println("CLIENT", i, "ServerComm: taling to ", hostspec)

	conn, err := net.Dial("tcp", hostspec)
    if err != nil {
    	fmt.Println(err.Error())
    	return
    }

    buffer_commit := make([]byte, 1024)

    fmt.Println("CLIENT", i, "Sending message")

    conn.Write(firstMessage)
    _, err = conn.Read(buffer_commit)
    if err != nil {
    	fmt.Println(err.Error())
    	return
    } 
    fmt.Println("CLIENT", i, "Response received, reporting to controller")

    // we now need to wait for the next step in the process.

    reportMsg := controllerMessage{i, buffer_commit}
    reportChan <- reportMsg // send back to runClientProtocol

    // now we'll use channel's by default blocking as a synchronisation
    // mechamism. Essentially I'm implementing message passing
    // here.

    fmt.Println("CLIENT", i, "Get aggregateBytes")

    var aggregateCommitmentBytes []byte
    aggregateCommitmentBytes = <- syncChan

    fmt.Println("CLIENT", i, "Got aggregateCommitmentBytes")

    // now we have our aggregate commitment, we need to send this
    // to the server also.

    buffer_response := make([]byte, 1026)
    secondMessage := []byte{COMMITMENT, 0}

    secondMessage = append(secondMessage, aggregateCommitmentBytes...)

    fmt.Println("CLIENT", i, "Sending aggregate commitment back to server.")

    conn.Write(secondMessage)
    _, err = conn.Read(buffer_response)
    if err != nil {
        fmt.Println("CLIENT", i, "Error getting response from server")
    	fmt.Println(err.Error())
    	return
    }

    fmt.Println("CLIENT", i, "Reporting response response to the controller, then exiting.")
    // report the outcome of the server response
    reportMsg = controllerMessage{i, buffer_response}
    reportChan <- reportMsg // send back to runClientProtocol

    // and then exit
    conn.Close()
    return
}


func runClientProtocol (configFilePath string) (bool, error) {

	// first stage, let's retrieve everything from
	// the configuration file that the client needs 

	var config SchnorrMGroupConfig

    suite :=  ed25519.NewAES128SHA256Ed25519(true)

	fcontents, err := ioutil.ReadFile(configFilePath)
    if err != nil {
    	fmt.Println("Error reading file")
        fmt.Println(err.Error())
        os.Exit(1)
    }

    err = json.Unmarshal(fcontents, &config)
    if err != nil {
    	fmt.Println("Error unmarshalling")
        fmt.Println(err.Error())
        os.Exit(1)
    }
    
    // and now, for our next trick, a random 1KB blob

    randomdata := make([]byte, 1024)
    _, err = rand.Read(randomdata)
    if err != nil {
        fmt.Println(err.Error())
    	return false, err
    }

    reportChan := make(chan controllerMessage)

    var syncChans [] chan []byte

    for i, _ := range config.Members {

        syncChan := make(chan []byte)
        syncChans = append(syncChans, syncChan)
        fmt.Println("CLIENT", "C", "Launching goroutine worker")

    	go serverComms(config, i, randomdata, reportChan, syncChan)
    }

    var respCount int = 0
    commitmentArray := make([]crypto.SchnorrMPublicCommitment, len(config.Members), len(config.Members))

    fmt.Println("CLIENT", "C", "Controller getting ready to receive")

    for {

    	select {
		case msg := <- reportChan:

			// we should probably check all our client threads have responded 
			// once and only once, but we won't

		    buf := bytes.NewBuffer(msg.Message)
    		commitment := crypto.SchnorrMPublicCommitment{}
    		err := abstract.Read(buf, &commitment, suite);
    		if err != nil {
                fmt.Println("CLIENT", "Read Error")
                fmt.Println(err.Error())
        		return false, err
    		}

    		// we have our abstract point.
			// let's go
            fmt.Println("CLIENT", "C", "Controller got message index", msg.MemberIndex)
            commitmentArray[msg.MemberIndex] = commitment

            respCount = respCount + 1

			
		default:
		}

		if respCount == len(config.Members) {
            // reset and break
            respCount = 0
			break
		}
    }

    fmt.Println("CLIENT", "C", "Controller received all responses, preparing to aggregate")


    // sum the points 
    aggregateCommmitment := crypto.SchnorrMComputeAggregateCommitment (suite, commitmentArray)
    collectiveChallenge := crypto.SchnorrMComputeCollectiveChallenge(suite, randomdata, aggregateCommmitment)
    

    bAggregateCommmitment := bytes.Buffer{} 
    abstract.Write(&bAggregateCommmitment, &aggregateCommmitment, suite)

    // report 
    for _, ch := range(syncChans) {
        fmt.Println("CLIENT", "C", "Sending aggcommitbytes back to workers")
        ch <- bAggregateCommmitment.Bytes()
    }

    // now wait for the server responses, aggregate them and compute
    // a signature from the combined servers.

    fmt.Println("CLIENT", "C", "Controller getting ready to receive")


    responseArray := make([]crypto.SchnorrMResponse, len(config.Members), len(config.Members))

    for {

        select {
        case msg := <- reportChan:

            // we should probably check all our client threads have responded 
            // once and only once, but we won't

            buf := bytes.NewBuffer(msg.Message)
            response := crypto.SchnorrMResponse{}
            err := abstract.Read(buf, &response, suite);
            if err != nil {
                return false, err
            }

            fmt.Println("CLIENT", "C", "Received from", msg.MemberIndex)

            // we have our abstract point.
            // let's go
            responseArray[msg.MemberIndex] = response

            respCount = respCount + 1
            fmt.Println("CLIENT", "C", "Received responses", respCount)

        default:
        }

        if respCount == len(config.Members) {
            break
        }
    }

    sig := crypto.SchnorrMComputeSignatureFromResponses(suite, collectiveChallenge, responseArray)

    fmt.Println("Signature created, is")
    fmt.Println(sig)

    return true, nil
}