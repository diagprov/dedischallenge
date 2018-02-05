package schnorrgs

/* This file implements Schnorr-multi signatures
   based on the schnorr.go file of this library.
*/

import (
	"fmt"
	"github.com/dedis/kyber"
)

// This is our internal tracking structure
// for subscriptions to the
// multiparty scheme. Everyone joins by being
// added here; we are ready to finalize we'll
// generate a SchnorrMultiSignaturePublicKey
type schnorrMState struct {
	Keysets []SchnorrSecretKV
	O       kyber.Point
	n       int
}

// This is the group public key.
// Conveniently it holds all the individual
// public keys
type SchnorrMultiSignaturePublicKey struct {
	suite string
	P     kyber.Point
}

// This structure holds T = g^v for
// group G. Don't send this to your clients -
// send .T only :)
type SchnorrMPrivateCommitment struct {
	suite string
	V     kyber.Scalar
	T     kyber.Point
}

// Represents a public commitment made by one party
type SchnorrMPublicCommitment struct {
	suite string
	T     kyber.Point
}

func (s *SchnorrMPrivateCommitment) PublicCommitment() SchnorrMPublicCommitment {
	return SchnorrMPublicCommitment{suite: s.suite, T: s.T}
}

func (s *SchnorrMultiSignaturePublicKey) GetSchnorrPK() SchnorrPublicKV {
	return SchnorrPublicKV{suite: s.suite, pP: s.P}
}

type SchnorrMAggregateCommmitment struct {
	suite string
	P     kyber.Point
}

type SchnorrMResponse struct {
	suite string
	R     kyber.Scalar
}

// Does exactly what it says on the tin: generates a random v and computes
// vG from the generator point G. Returns a private commitment structure.
func SchnorrMGenerateCommitment(suite CryptoSuite) SchnorrMPrivateCommitment {
	v := suite.Scalar().Pick(suite.RandomStream()) // some v
	t := suite.Point().Mul(v, nil)                 // g^v = t
	return SchnorrMPrivateCommitment{T: t, V: v}
}

// (Either side) This function computes the shared public key
// by adding public key points over the curve group.
// Since each public key is already g*k where g is the group
// generator this is all we need to do
func SchnorrMComputeSharedPublicKey(suite CryptoSuite,
	pkeys []SchnorrPublicKV, prikeys []SchnorrSecretKV) SchnorrMultiSignaturePublicKey {
	var P kyber.Point = pkeys[0].pP

	fmt.Println("P= " + P.String())
	for _, pkey := range pkeys[1:] {
		fmt.Println("Adding " + pkey.pP.String())
		P.Add(P, pkey.pP)
		fmt.Println("P= " + P.String())
	}

	// Additional but unnecessary verification from debugging.
	var x kyber.Scalar = prikeys[0].s
	for _, pxk := range prikeys[1:] {
		x.Add(x, pxk.s)
	}
	var PX = suite.Point().Mul(x, nil)
	if !PX.Equal(P) {
		fmt.Println("Points are not equal!!")
	}
	return SchnorrMultiSignaturePublicKey{suite: pkeys[0].suite, P: P}
}

// (Client side) The client requiring the n-signature scheme
// performs the addition of points under the elliptic curve group
// and returns the aggregate commitment as a raw point
// in bytes for transmission to the server
func SchnorrMComputeAggregateCommitment(suite CryptoSuite,
	pcommits []SchnorrMPublicCommitment) SchnorrMAggregateCommmitment {
	var P kyber.Point = pcommits[0].T
	fmt.Println("P= " + P.String())
	for _, pcommit := range pcommits[1:] {
		fmt.Println("Adding " + pcommit.T.String())
		P.Add(P, pcommit.T)
		fmt.Println("P= " + P.String())
	}
	k := SchnorrMAggregateCommmitment{suite: pcommits[0].suite, P: P}
	return k
}

// (Either side) This function takes the aggregate public commitment
// r and returns sha3(m||r) for a given message.
func SchnorrMComputeCollectiveChallenge(suite CryptoSuite,
	msg []byte,
	pubCommit SchnorrMAggregateCommmitment) (kyber.Scalar, error) {

	scalar, err := SchnorrHashPointsMsgToScalar(suite, pubCommit.P, msg)
	return scalar, err
}

// (Server side) This function reads the collective challenge
// from the wire, generates and serializes a response
// to that as a raw "secret"
func SchnorrMUnmarshallCCComputeResponse(suite CryptoSuite,
	kv SchnorrSecretKV,
	privatecommit SchnorrMPrivateCommitment,
	c kyber.Scalar) SchnorrMResponse {

	s := suite.Scalar()
	s.Mul(kv.s, c).Sub(privatecommit.V, s)

	return SchnorrMResponse{privatecommit.suite, s}
}

// this function produces a signature given a response from the server.
func SchnorrMComputeSignatureFromResponses(suite CryptoSuite,
	c kyber.Scalar,
	responses []SchnorrMResponse) SchnorrSignature {

	var e kyber.Scalar = responses[0].R
	fmt.Println("e= " + e.String())

	for _, response := range responses[1:] {
		fmt.Println("Adding " + response.R.String())
		e.Add(e, response.R)
		fmt.Println("e= " + e.String())
	}

	return SchnorrSignature{S: c, E: e}

}
