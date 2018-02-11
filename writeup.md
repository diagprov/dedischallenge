
# Writeup

## Notes on a cryptographic level

I've seen the Schnorr public signature scheme as given in the Dedis library. 
Having written my own last time around, I decided to continue with a "standard" 
Schnorr signature scheme as given on [Schnorr Signatures, wikipedia][wiki-schnorr].
Point / message hashing uses the scheme

    Blake2b(P||M)

Rather than the given sha2 example.

## Completed tasks / navigating your way through my code:

I have split my code up into several components based largely on what I did for 
the original challenge. The components are as follows:

 * schnorrgs, the Schnorr Group Signatures code, handles all of the crypto, 
   key load/store, and corresponding unit tests to validate I've done that 
   correctly.
 * keytool is a small utility to create key files and to create "group" schemes, 
   as I ignored the "2 parties" limitation - my code will accept arbitrary 
   numbers of running servers.
 * notaryclient, notaryserver are challenge 1. Essentially, you can launch 
   a notary server and then have notaryclient issue arbitrary signing requests 
   as needed. Notaryclient checks the signature is valid, but does no more 
   than this.
 * sthresholdserver, sthresholdclient are the multi-party threshold signature 
   server and client respectively. Note that there can be N running 
   sthresholdserver instances, but only one sthresholdclient.
   sthresholdclient validates the signature it receives using the group public 
   key.

## Using these tools

In the directory `test` you will find three scripts that demonstrate tool usage. 
challenge1 generates a public/private key pair, laucches a notary server, 
requests a signature then shuts down.

Challenge2 generates two key pairs and a group config file, then launches two 
servers. The client is then fed the group config file and communicates to 
obtain a group signature.

Challenge2_10 does the same thing, but demonstrates doing this with 10 servers.

You'll need to build the binaries using `go build` and copy them to the test 
directory. I tried to write a makefile to automate this but the go tool doesn't 
play well with that. Alternatively copy the scripts to your go/bin directory 
and go install the various tools.

## Improvements since last time

I've tried to make a bit more of an effort with my coding this time in some 
areas, for example:

 * Servers retrieve signals and cleanly exit
 * I've tried to gracefully handle all error cases.
 * Almost everything in schorrgs has unit tests
 * The shell scripts act as a kind of integration tests.

What's missing from the point of view of a proper software project?

 * Each of the tools needs its own unit testing with pluggable network 
   interfaces so we can make sure stuff doesn't randomly break.
 * The tools don't do super input validation, so accept and crash when fed 
   private keys. Not great.

## Questions you might have

 * Q: Why do the crypto key types contain the suite name?
   A: I had it in mind to try to prevent feeding different suite types to 
      the signing code, although the type system should protect against this 
      as well, we might be able to Marshal a NIST point from an Edwards point 
      and so on.
      Also, if you wanted to sign those keys, it helps to bind to the algorithm 
      used, thus, sign over type+key.
 * Q: You used Encode and Decode in places, and then worked out using MarshalTo... 
      type constructs, what?
   A: yes, I don't write much Go, so, I picked up the style of kyber as I went.
 * Q: I don't like your coding style.
   A: That's not a question. In any event a) I'm coding for speed, b) everyone 
      has their own style, if you don't like it I recommend "people skills" as 
      a first approach.
 * Q: I don't like the code organisation!
   A: Again, not a question, but: this is what I did 3 years ago and I've only 
      adapted it for kyber.
 * Q: Why didn't you use a/b/c/d in Go?
   A: I didn't know about it, or I didn't have time, or both.

## Is there a github repository?

Yes. github.com/diagprov/dedischallenge

   [wiki-schnorr]: https://en.wikipedia.org/wiki/Schnorr_signature
