package schnorrgs

// This file implements Schnorr signature scheme
// Mostly based on your implementation except
// 1) I used wikipedia's variable names as my reference,
//    not your letters. Sorry.
// 2) I reworked hashing to use SHA3.
// 3) Generating keys grabs a random 128-bit blob from
//    /dev/urandom instead of  using a fixed example.
// 4) likewise, k the randomly chosen data in our signature
//    is also read from /dev/urandom.

import (
	"bytes"
	"github.com/dedis/kyber"
)

// Represents a Schnorr signature.
type SchnorrSignature struct {
	S kyber.Scalar
	E kyber.Scalar
}

// Encode produces a byte array from a signature structure
// I should probably have named this MarshalTo to be consistent
// with go.
func (sig SchnorrSignature) Encode() ([]byte, error) {

	var b bytes.Buffer
	_, err := sig.S.MarshalTo(&b)
	if err != nil {
		return nil, err
	}

	_, err = sig.E.MarshalTo(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// This method takes a binary string and appropriate suite and
// attempts to decode a signature from it.
func DecodeSchnorrSignature(suite CryptoSuite, sig []byte) (SchnorrSignature,
	error) {

	var S = suite.Scalar()
	var E = suite.Scalar()
	var scalar_size = suite.Scalar().MarshalSize()

	err := S.UnmarshalBinary(sig[:scalar_size])
	if err != nil {
		return SchnorrSignature{}, err
	}

	err = E.UnmarshalBinary(sig[scalar_size:])
	if err != nil {
		return SchnorrSignature{}, err
	}

	return SchnorrSignature{S: S, E: E}, nil
}

// Signs a given message and returns the signature.
// If no signature is possible due to an error
// returns the error in the second retval.
func SchnorrSign(suite CryptoSuite,
	kv SchnorrSecretKV,
	msg []byte) (SchnorrSignature, error) {

	k := suite.Scalar().Pick(suite.RandomStream()) // some k
	R := suite.Point().Mul(k, nil)                 // r = g^k

	// e = H(r||M)
	e, err := SchnorrHashPointsMsgToScalar(suite, R, msg)
	if err != nil {
		return SchnorrSignature{}, err
	}
	s := suite.Scalar().Zero()
	s.Mul(kv.s, e).Sub(k, s) // k - xe

	sig := SchnorrSignature{S: s, E: e}

	return sig, nil
}

func SchnorrSignBinary(suite CryptoSuite,
	kv SchnorrSecretKV,
	msg []byte) ([]byte, error) {

	sig, err := SchnorrSign(suite, kv, msg)
	if err != nil {
		return nil, err
	}
	sige, err := sig.Encode()
	return sige, err
}

// Checks the signature against
// the message
func SchnorrVerify(suite CryptoSuite,
	kp SchnorrPublicKV,
	msg []byte, signature SchnorrSignature) (bool, error) {

	var sG, eY, R kyber.Point
	sG = suite.Point().Mul(signature.S, nil)   // sG
	eY = suite.Point().Mul(signature.E, kp.pP) // eY
	R = suite.Point().Add(sG, eY)              // sG +eY

	ev, err := SchnorrHashPointsMsgToScalar(suite, R, msg)
	if err != nil {
		return false, err
	}

	return ev.Equal(signature.E), nil
}

func SchnorrVerifyBinary(suite CryptoSuite,
	kp SchnorrPublicKV,
	msg []byte, sig []byte) (bool, error) {

	signature, err := DecodeSchnorrSignature(suite, sig)
	if err != nil {
		return false, err
	}

	return SchnorrVerify(suite, kp, msg, signature)
}

// The schnorrGenerateKeypair does exactly that -
// it generates a valid keypair for later use
// in producing signatures.
// I wanted to add a little bit of proper key
// management to the process but I couldn't work out
// how to pass a simple random stream to suite.Secret().Pick().
// I looked into Go streams very briefly  but decided
// I was spending too much time on that
// instead I passed /dev/urandom through the cipher
// interface.
func SchnorrGenerateKeypair(suite CryptoSuite) (SchnorrSecretKV, error) {

	x := suite.Scalar().Pick(suite.RandomStream()) // some x
	y := suite.Point().Mul(x, nil)                 // y = g^x \in G, DLP.

	return SchnorrSecretKV{suite: "BlakeSHA256Ed25519", s: x, pP: y}, nil
}
