package schnorrgs

/* This file implements Schnorr-multi signatures
   based on the schnorr.go file of this library.
*/

import (
	"bytes"
	"github.com/dedis/kyber"
	"io"
)

type SchnorrMSCommitment struct {
	v kyber.Scalar
	T kyber.Point
}

func (sc SchnorrMSCommitment) MarshalBinary() ([]byte, error) {
	var result bytes.Buffer

	b, err := sc.v.MarshalBinary()
	if err != nil {
		return nil, err
	}
	result.Write(b)

	b, err = sc.T.MarshalBinary()
	if err != nil {
		return nil, err
	}
	result.Write(b)

	return result.Bytes(), nil
}

func (sc SchnorrMSCommitment) MarshalTo(w io.Writer) {
	sc.v.MarshalTo(w)
	sc.T.MarshalTo(w)
}

func (sc SchnorrMSCommitment) UnmarshalBinary(suite CryptoSuite, b []byte) error {
	v := suite.Scalar()
	T := suite.Point()

	err := v.UnmarshalBinary(b[:sc.v.MarshalSize()])
	if err != nil {
		return err
	}
	err = T.UnmarshalBinary(b[sc.v.MarshalSize():sc.T.MarshalSize()])
	if err != nil {
		return err
	}
	sc.T = T
	sc.v = v
	return nil
}

func (msc SchnorrMSCommitment) GetPublicCommitment() SchnorrMSPublicCommitment {
	return SchnorrMSPublicCommitment{T: msc.T}
}

type SchnorrMSPublicCommitment struct {
	T kyber.Point
}

func (pc SchnorrMSPublicCommitment) MarshalBinary() ([]byte, error) {
	var result bytes.Buffer

	b, err := pc.T.MarshalBinary()
	if err != nil {
		return nil, err
	}
	result.Write(b)

	return result.Bytes(), nil
}

func (pc SchnorrMSPublicCommitment) MarshalTo(w io.Writer) {
	pc.T.MarshalTo(w)
}

func (pc SchnorrMSPublicCommitment) UnmarshalBinary(suite CryptoSuite, b []byte) error {
	T := suite.Point().Null()
	err := T.UnmarshalBinary(b)
	if err != nil {
		return err
	}
	pc.T = T
	return nil
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
