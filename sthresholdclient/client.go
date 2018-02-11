package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/diagprov/dedischallenge/schnorrgs"
	"io/ioutil"
	"net"
	"os"
)

type SchnorrMMember struct {
	HostName string
	Port     int
	PKey     string
}

func (m SchnorrMMember) GetPKeyAsKV() (*schnorrgs.SchnorrPublicKV, error) {
	return schnorrgs.NewSchnorrPublicKeyFromString(m.PKey)
}

type SchnorrMGroupConfig struct {
	JointKey string
	Members  []SchnorrMMember
}

func (m SchnorrMGroupConfig) GetJointKeyAsKV() (*schnorrgs.SchnorrPublicKV, error) {
	return schnorrgs.NewSchnorrPublicKeyFromString(m.JointKey)
}

const (
	MESSAGE    byte = 1
	COMMITMENT byte = 2
)

type controllerMessage struct {
	MemberIndex int
	Message     []byte // if we don't keep this generic type enforcement
	// will stop us using a single channel.
}

func serverComms(gconfig SchnorrMGroupConfig, i int, msg []byte, reportChan chan controllerMessage, syncChan chan []byte) {

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
	aggregateCommitmentBytes = <-syncChan

	fmt.Println("CLIENT", i, "Got aggregateCommitmentBytes")

	// now we have our aggregate commitment, we need to send this
	// to the server also.

	buffer_response := make([]byte, 1024)
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

func runClientProtocol(configFilePath string) (bool, error) {

	// first stage, let's retrieve everything from
	// the configuration file that the client needs

	var config SchnorrMGroupConfig

	suite, _ := schnorrgs.GetSuite("BlakeSHA256Ed25519")

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

	var syncChans []chan []byte

	for i, _ := range config.Members {

		syncChan := make(chan []byte)
		syncChans = append(syncChans, syncChan)
		fmt.Println("CLIENT", "C", "Launching goroutine worker")

		go serverComms(config, i, randomdata, reportChan, syncChan)
	}

	var respCount int = 0
	fmt.Println("CLIENT", "C", "Allocated space for", len(config.Members))
	commitmentArray := make([]schnorrgs.SchnorrMSPublicCommitment, len(config.Members))

	fmt.Println("CLIENT", "C", "Controller getting ready to receive")

	for {

		select {
		case msg := <-reportChan:

			// we should probably check all our client threads have responded
			// once and only once, but we won't

			commitment := schnorrgs.SchnorrMSPublicCommitment{}

			err = commitment.UnmarshalBinary(suite, msg.Message)
			if err != nil {
				fmt.Println("CLIENT", "C", "Decode Read Error")
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
			break
		}
	}

	fmt.Println("CLIENT", "C", "Controller received all responses, preparing to aggregate")

	// sum the points
	aggregateCommmitment := schnorrgs.SchnorrMSAggregateCommitment(suite, commitmentArray)
	collectiveChallenge, _ := schnorrgs.SchnorrMSComputeCollectiveChallenge(suite, aggregateCommmitment, randomdata)

	bAggregateCommmitment, err := aggregateCommmitment.MarshalBinary()
	if err != nil {
		fmt.Println("Error")
		return false, err
	}

	// report
	for _, ch := range syncChans {
		fmt.Println("CLIENT", "C", "Sending aggcommitbytes back to workers")
		ch <- bAggregateCommmitment
	}

	// now wait for the server responses, aggregate them and compute
	// a signature from the combined servers.

	fmt.Println("CLIENT", "C", "Controller getting ready to receive")

	responseArray := make([]kyber.Scalar, len(config.Members))
	respCount = 0

	for {
		select {
		case msg := <-reportChan:

			// we should probably check all our client threads have responded
			// once and only once, but we won't
			response := suite.Scalar().Zero()
			scalar_size := suite.Scalar().MarshalSize()

			err := response.UnmarshalBinary(msg.Message[0:scalar_size])

			if err != nil {
				fmt.Println("CLIENT", "C", "Error!")
				fmt.Println(err.Error())
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

	combined_response := schnorrgs.SchnorrMSComputeCombinedResponse(suite, responseArray)

	sig := schnorrgs.SchnorrMSCreateSignature(suite, collectiveChallenge, combined_response)

	fmt.Println("Signature created, is")
	fmt.Println(sig)

	sharedpubkey, err := config.GetJointKeyAsKV()
	if err != nil {
		fmt.Println("Error during Verification")
		fmt.Println(err.Error())
		return false, err
	}

	fmt.Println("Verifying Signature with shared public key")

	verified, err := schnorrgs.SchnorrVerify(suite,
		*sharedpubkey,
		randomdata, sig)
	if err != nil {
		fmt.Println("Error during Verification")
		fmt.Println(err.Error())
		return false, err
	}
	if verified == false {
		fmt.Println("Verification of signature failed.")
		return false, nil
	}
	fmt.Println("Signature verified OK!")
	return true, nil
}
