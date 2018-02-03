package main

import (
	"fmt"
	"github.com/dedis/kyber/edwards/ed25519"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	"io/ioutil"
	"net"
	"os"
	"vennard.ch/crypto"
)

/* These variables form the command line parameters of the keytool utility.
   The kingpin processor is much more to my liking than just about any
   other I've seen in a couple of languages - even boost::program_options isn't quite
   this good.
*/
var (
	app               = kingpin.New("sigserv3", "Blind signature server - signs (partially blindly) a message provided by sigcli3")
	appPrivatekeyfile = app.Arg("privatekey", "Path to schnorr private key").Required().String()
	appInfo           = app.Arg("info", "Output file path to write (appends .pub, .pri)").Required().String()
	appPort           = app.Arg("port", "Listen on port").Int()
)

func LoadInfo(path string) ([]byte, error) {
	fcontents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return fcontents, nil
}

/* runs through the process of setting up the server as specified in the args */
func main() {

	kingpin.MustParse(app.Parse(os.Args[1:]))

	var port int = *appPort
	var kfilepath string = *appPrivatekeyfile
	var kinfopath string = *appInfo

	fmt.Printf("Sigserv3 - listening on port %d.\n", port)

	suite := ed25519.NewAES128SHA256Ed25519(true)
	kv, err := crypto.SchnorrLoadKeypair(kfilepath, suite)
	if err != nil {
		fmt.Println("Error " + err.Error())
		return
	}

	info, err := LoadInfo(kinfopath)
	if err != nil {
		fmt.Println("Error " + err.Error())
		return
	}

	// I don't know if there's a way to
	// do std::bind-like behaviour in GO.
	// for C++ what I'd do is pretty simple:
	// newfunc := std::bind(&func, args to bind)
	var signBlindImpl connectionhandler = func(conn net.Conn) {
		signBlindlySchnorr(conn, suite, kv, info)
	}
	serve(port, signBlindImpl)
}
