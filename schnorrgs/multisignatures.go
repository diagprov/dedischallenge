package schnorrgs

/* This file implements Schnorr-multi signatures
   based on the schnorr.go file of this library.
*/

import (
	"github.com/dedis/kyber"
)

type SchnorrMSCommitment struct {
	v kyber.Scalar
	T kyber.Point
}

func (msc SchnorrMSCommitment) GetPublicCommitment() SchnorrMSPublicCommitment {
	return SchnorrMSPublicCommitment{T: msc.T}
}

type SchnorrMSPublicCommitment struct {
	T kyber.Point
}

func SchnorrMSGenerateCommitment(suite CryptoSuite) SchnorrMSCommitment {

	v := suite.Scalar().Pick(suite.RandomStream())
	T := suite.Point().Mul(v, nil)

	return SchnorrMSCommitment{v: v, T: T}
}

func SchnorrMSAggregateCommitment(suite CryptoSuite,
	commitments []SchnorrMSPublicCommitment) SchnorrMSPublicCommitment {

	aggCommitment := suite.Point().Null()

	for _, commitment := range commitments {
		aggCommitment = suite.Point().Add(aggCommitment, commitment.T)
	}

	return SchnorrMSPublicCommitment{T: aggCommitment}
}

func SchnorrMSComputeSharedPublicKey(suite CryptoSuite,
	pubkeys []SchnorrPublicKV) SchnorrPublicKV {

	sharedpubkey := suite.Point().Null()

	for _, key := range pubkeys {
		sharedpubkey = suite.Point().Add(sharedpubkey, key.pP)
	}

	return SchnorrPublicKV{suite: "BlakeSHA256Ed25519", pP: sharedpubkey}
}

func SchnorrMSComputeCollectiveChallenge(suite CryptoSuite,
	aggcommit SchnorrMSPublicCommitment, msg []byte) (kyber.Scalar, error) {
	return SchnorrHashPointsMsgToScalar(suite, aggcommit.T, msg)
}

func SchnorrMSComputeResponse(suite CryptoSuite,
	c kyber.Scalar, privkey SchnorrSecretKV,
	privcommit SchnorrMSCommitment) kyber.Scalar {

	r := suite.Scalar().Zero()
	r = r.Mul(c, privkey.s)
	r = r.Sub(privcommit.v, r)

	return r
}

func SchnorrMSComputeCombinedResponse(suite CryptoSuite,
	responses []kyber.Scalar) kyber.Scalar {

	tr := suite.Scalar().Zero()

	for _, r := range responses {
		tr = suite.Scalar().Add(tr, r)
	}

	return tr
}

func SchnorrMSCreateSignature(suite CryptoSuite, c kyber.Scalar,
	r kyber.Scalar) SchnorrSignature {

	return SchnorrSignature{S: r, E: c}
}
