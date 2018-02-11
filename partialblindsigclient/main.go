package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/diagprov/dedischallenge/schnorrgs"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	"io/ioutil"
	"net"
	"os"
)

/* variables for sigcli3. Try sigcli3 --help to see what you should be passing */
var (
	app               = kingpin.New("partialblindsigclient", "Client for partially blind signature scheme implementation")
	appPrivatekeyfile = app.Arg("privatekey", "Path to schnorr public key").Required().String()
	appInfo           = app.Arg("info", "Output file path to write (appends .pub, .pri)").Required().String()
	appHostspec       = app.Arg("host", "Listen on port").Required().String()
)

/* this function loads the random binary blob used as the
   blind key and specified in path
*/
func LoadInfo(path string) ([]byte, error) {
	fcontents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return fcontents, nil
}

/* Runs through the "user" side of the protocol i.e. the party
   requesting a partially blind signature */
func main() {

	kingpin.MustParse(app.Parse(os.Args[1:]))

	var kfilepath string = *appPrivatekeyfile
	var kinfopath string = *appInfo
	var hostspec string = *appHostspec

	suite := edwards25519.NewBlakeSHA256Ed25519()

	fmt.Println("CLIENT", "Connecting to", hostspec)

	pubKey, err := schnorrgs.SchnorrLoadPubkey(kfilepath)
	if err != nil {
		fmt.Println("CLIENT", "Error loading public key"+err.Error())
		return
	}

	info, err := LoadInfo(kinfopath)
	if err != nil {
		fmt.Println("CLIENT", "Error loading info"+err.Error())
		return
	}

	message := make([]byte, 1024)
	_, err = rand.Read(message)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	conn, err := net.Dial("tcp", hostspec)
	if err != nil {
		fmt.Println("CLIENT", "Error connecting to server", err.Error())
		return
	}
	defer conn.Close()

	// first up, let's receive the signer's parameter set

	buffer := make([]byte, 1028)
	_, err = conn.Read(buffer)
	if err != nil {
		fmt.Println("CLIENT", "Error reading from server", err.Error())
		return
	}

	var userPublicParams schnorrgs.WISchnorrPublicParams
	userPublicParams.UnmarshalBinary(buffer)

	// now we've got that, complete the challenge phase (i.e. let's generate E)
	challenge, userPrivateParams, err := schnorrgs.ClientGenerateChallenge(suite, userPublicParams, pubKey, info, message)
	if err != nil {
		fmt.Println("CLIENT", "Error generating challenge", err.Error())
		return
	}

	// encode and send to server.
	challengebuffer := bytes.Buffer{}
	challenge.MarshalTo(challengebuffer)
	conn.Write(challengebuffer.Bytes())

	// and now we wait for the server to respond to this:
	secondread := make([]byte, 1024)
	_, err = conn.Read(secondread)
	if err != nil {
		fmt.Println("CLIENT", "Error reading from server", err.Error())
		return
	}

	var responseMessage schnorrgs.WISchnorrResponseMessage
	decodeBuffer = bytes.NewBuffer(secondread)
	err = abstract.Read(decodeBuffer, &responseMessage, suite)
	if err != nil {
		fmt.Println("CLIENT", "Error reading response", err.Error())
		return
	}

	// we've got the response message, time to sign and check.

	// finally, we can sign the message and check it verifies.
	sig, worked := schnorrgs.ClientSignBlindly(suite, userPrivateParams, responseMessage, pubKey, message)

	//fmt.Println(blindSignature)

	if worked != true {
		fmt.Println("CLIENT", "Error preforming blind signature")
		return
	}

	// now verify this worked fine.
	result, err := schnorrgs.VerifyBlindSignature(suite, pubKey, sig, info, message)

	if err != nil {
		fmt.Println("CLIENT", "Error handling signature verification", err.Error())
		return
	}
	if result != true {
		fmt.Println("CLIENT", "Signature did not correctly verify.")
		return
	}

	fmt.Println("CLIENT", "Signature OK -", sig)

	return
}
