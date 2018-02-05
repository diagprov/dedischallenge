package schnorrgs

/* This file implements Schnorr-multi signatures
   based on the schnorr.go file of this library.
*/

import (
	"crypto/rand"
	"fmt"
	"github.com/dedis/kyber"
	"golang.org/x/crypto/blake2b"
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
	return SchnorrMPublicCommitment{s.suite, s.T}
}

func (s *SchnorrMultiSignaturePublicKey) GetSchnorrPK() SchnorrPublicKV {
	return SchnorrPublicKV{s.suite, s.P}
}

type SchnorrMAggregateCommmitment struct {
	suite string
	P     kyber.Point
}

type SchnorrMResponse struct {
	suite string
	R     kyber.Scalar
}

func SchnorrMGenerateCommitment(suite CryptoSuite) (SchnorrMPrivateCommitment, error) {
	rsource := make([]byte, 16)
	_, err := rand.Read(rsource)
	if err != nil {
		return SchnorrMPrivateCommitment{}, err
	}
	// I have no idea if I just encrypted randomness or not
	// I'm hoping this just reads the state out.

	v := suite.Scalar().Pick(suite.RandomStream()) // some v
	t := suite.Point().Mul(v, nil)                 // g^v = t
	return SchnorrMPrivateCommitment{T: t, V: v}, nil
}

// (Either side) This function computes the shared public key
// by adding public key points over the curve group.
// Since each public key is already g*k where g is the group
// generator this is all we need to do
func SchnorrMComputeSharedPublicKey(suite CryptoSuite,
	pkeys []SchnorrPublicKV) SchnorrMultiSignaturePublicKey {
	var P kyber.Point = pkeys[0].pP

	for _, pkey := range pkeys[1:] {
		P.Add(P, pkey.pP)
	}
	return SchnorrMultiSignaturePublicKey{pkeys[0].suite, P}
}

// (Client side) The client requiring the n-signature scheme
// performs the addition of points under the elliptic curve group
// and returns the aggregate commitment as a raw point
// in bytes for transmission to the server
func SchnorrMComputeAggregateCommitment(suite CryptoSuite,
	pcommits []SchnorrMPublicCommitment) SchnorrMAggregateCommmitment {
	var P kyber.Point = pcommits[0].T

	for _, pcommit := range pcommits[1:] {
		P.Add(P, pcommit.T)
	}
	k := SchnorrMAggregateCommmitment{pcommits[0].suite, P}
	return k

	/*buf := bytes.Buffer{}
	  abstract.Write(&buf, &k, suite)
	  return buf.Bytes()*/
}

// (Either side) This function takes the aggregate public commitment
// r and returns sha3(m||r) for a given message.
func SchnorrMComputeCollectiveChallenge(suite CryptoSuite,
	msg []byte,
	pubCommit SchnorrMAggregateCommmitment) ([]byte, error) {

	h, err := blake2b.New512(nil)
	if err != nil {
		return nil, err
	}
	pubCommit.P.MarshalTo(h)
	h.Write(msg)
	digest := h.Sum(nil)
	return digest, nil
}

// (Server side) This function reads the collective challenge
// from the wire, generates and serializes a response
// to that as a raw "secret"
func SchnorrMUnmarshallCCComputeResponse(suite CryptoSuite,
	kv SchnorrSecretKV,
	privatecommit SchnorrMPrivateCommitment,
	cc []byte) SchnorrMResponse {

	c := suite.Scalar().Pick(suite.RandomStream())
	r := suite.Scalar()
	r.Mul(c, kv.s).Sub(privatecommit.V, r)

	return SchnorrMResponse{privatecommit.suite, r}
}

// this function produces a signature given a response from the server.
func SchnorrMComputeSignatureFromResponses(suite CryptoSuite,
	cc []byte,
	responses []SchnorrMResponse) SchnorrSignature {
	c := suite.Scalar().Pick(suite.RandomStream()) // H(m||r)

	var r kyber.Scalar = responses[0].R

	for _, response := range responses[1:] {
		r.Add(r, response.R)
	}

	return SchnorrSignature{S: r, E: c}
}
