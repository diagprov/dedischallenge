
package main

import (
	"fmt"
	"crypto/rand"
	"bytes"
	"os"
	"strconv"
	"strings"
    kingpin "gopkg.in/alecthomas/kingpin.v2"
)

/* These variables form the command line parameters of the keytool utility.
   The kingpin processor is much more to my liking than just about any 
   other I've seen in a couple of languages - even boost::program_options isn't quite 
   this good.
   */
var (

	app = kingpin.New("keytool", "Command line keygen tool for Schnorr work")

	genCmd = app.Command("gen", "Generate a new server instance pub,pri keypair")
	genCmdOutput = genCmd.Arg("output", "Output file path to write (appends .pub, .pri)").Required().String()

	groupCmd = app.Command("mkgroup", "Create a Schnorr Multisignature group configuration file")
	groupCmdOutput = groupCmd.Arg("output", "Write the output file to this path").Required().String()
	groupCmdHost = groupCmd.Arg("host:port,pathtokey", "triplet  indicating host to add").Required().Strings()

	randomInfCmd = app.Command("raninf", "Generate a random blob of shared information for Partially-Blind")
	randomInfCmdOutput = randomInfCmd.Arg("output", "Output file path to write").Required().String()
)


/* this function is effectively dd if=/dev/urandom of=$PATH bs=1 count=16
   that is, we copy 16 bytes of cryptographically secure random junk to 
   the output file. The only reason for this is for convenience 
   for the agreed information file 
   between the signer and the user in blind signatures.
   Present in the entry file because it is hardly worth a separate file. */
func createRandomSharedInfoInFile(path string) error {

	rsource := make([]byte, 16)
    _, err := rand.Read(rsource)
    if err != nil {
        return err
    }

    buf := bytes.NewBuffer(rsource)

    f, err := os.OpenFile(path, os.O_CREATE | os.O_RDWR, 0644)
    if err != nil { return err }
    defer f.Close()
    _, err = f.Write(buf.Bytes())
    return err
}

/* Entry point to the keytool utility. Switches based on the command line argument structure
   given above.
   Parses all  arguments except os.Args[0], the program name.
 */
func main() {
	
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case genCmd.FullCommand():
		runKeyGen(*genCmdOutput)
	case groupCmd.FullCommand():

		var outputfile string = *groupCmdOutput
		var parties []SchnorrMSHostSpec

		for _, item := range *groupCmdHost {
			parts := strings.Split(item, ",")
			hostspec := parts[0]
			pubkeyfile := parts[1]

			hsparts := strings.Split(hostspec, ":")
			host := hsparts[0]
			port, err := strconv.Atoi(hsparts[1])
			if err != nil {
				fmt.Println("Error invalid argument")
				fmt.Println(err.Error())
				os.Exit(1)
			}

			party := SchnorrMSHostSpec{host, port, pubkeyfile}
			parties = append(parties, party)
		}

		runMultiSignatureGen(parties, outputfile)
	case randomInfCmd.FullCommand():
		var outputfile string = *randomInfCmdOutput
		err := createRandomSharedInfoInFile(outputfile)
		if err != nil {
			fmt.Println("Error", err.Error())
		} else {
			fmt.Println("Random bytes written to", outputfile)
		}
	}
}
