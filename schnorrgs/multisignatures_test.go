package schnorrgs

import (
	"crypto/rand"
	"fmt"
	"github.com/dedis/kyber/group/edwards25519"
	"testing"
)

// This test function runs through a 2-party
// Schnorr Multi-Signature Scheme as described in the notes.
// This code is my TDD-code to validate the crypto
// before using it in the network stack properly
// The code file is commented with the relevant steps.
func TestMultisignature2ServerScenario(t *testing.T) {

	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Generate ourselves two keypairs, one for each "server"
	kv_1, err := SchnorrGenerateKeypair(suite)
	if err != nil {
		t.Error(err.Error())
	}
	kv_2, err := SchnorrGenerateKeypair(suite)
	if err != nil {
		t.Error(err.Error())
	}

	// Make a random message and "send" it to the server
	randomdata := make([]byte, 1024)
	_, err = rand.Read(randomdata)
	if err != nil {
		t.Error(err.Error())
		return
	}

	// client side
	// compute the shared public key given the public keys of each
	// participant.

	pks := []SchnorrPublicKV{kv_1.GetPublicKeyset(), kv_2.GetPublicKeyset()}
	sharedpubkey := SchnorrMComputeSharedPublicKey(suite, pks, []SchnorrSecretKV{kv_1, kv_2})

	// SERVER
	// In response to this each server will generate two
	// arbitrary secrets and respond with a commitment.
	// which it then sends to the client.
	commit1 := SchnorrMGenerateCommitment(suite)
	commit2 := SchnorrMGenerateCommitment(suite)

	// Client side
	commit_array := []SchnorrMPublicCommitment{commit1.PublicCommitment(), commit2.PublicCommitment()}
	aggregate_commitment := SchnorrMComputeAggregateCommitment(suite,
		commit_array)

	// client and servers
	collective_challenge, err := SchnorrMComputeCollectiveChallenge(suite,
		randomdata,
		aggregate_commitment)

	if err != nil {
		t.Error("Error computing collective challenge")
		t.Error(err.Error())
	}

	// servers respond to client with responses
	response_1 := SchnorrMUnmarshallCCComputeResponse(suite, kv_1, commit1,
		collective_challenge)
	response_2 := SchnorrMUnmarshallCCComputeResponse(suite, kv_2, commit2,
		collective_challenge)

	// finally, we compute a signature given the responses.
	responsearr := []SchnorrMResponse{response_1, response_2}

	sig := SchnorrMComputeSignatureFromResponses(suite, collective_challenge,
		responsearr)

	// After all that, we should be able to validate the signature
	// against the group public key. First we serialize the signature

	bsig, err := sig.Encode()
	if err != nil {
		t.Error("Error during Verification")
		t.Error(err.Error())
	}

	verified, err := SchnorrVerify(suite,
		sharedpubkey.GetSchnorrPK(),
		randomdata, bsig)

	if err != nil {
		t.Error("Error during Verification")
		t.Error(err.Error())
	}
	if verified == false {
		t.Error("Verification of signature failed.")
	}
}

func TestMultisignature5ServerScenario(t *testing.T) {

	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Generate ourselves two keypairs, one for each "server"
	kv_1, err := SchnorrGenerateKeypair(suite)
	if err != nil {
		t.Error(err.Error())
	}
	kv_2, err := SchnorrGenerateKeypair(suite)
	if err != nil {
		t.Error(err.Error())
	}
	kv_3, err := SchnorrGenerateKeypair(suite)
	if err != nil {
		t.Error(err.Error())
	}
	kv_4, err := SchnorrGenerateKeypair(suite)
	if err != nil {
		t.Error(err.Error())
	}
	kv_5, err := SchnorrGenerateKeypair(suite)
	if err != nil {
		t.Error(err.Error())
	}

	// Make a random message and "send" it to the server
	randomdata := make([]byte, 1024)
	_, err = rand.Read(randomdata)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// client side
	// compute the shared public key given the public keys of each
	// participant.

	pks := []SchnorrPublicKV{kv_1.GetPublicKeyset(),
		kv_2.GetPublicKeyset(),
		kv_3.GetPublicKeyset(),
		kv_4.GetPublicKeyset(),
		kv_5.GetPublicKeyset()}
	sharedpubkey := SchnorrMComputeSharedPublicKey(suite, pks, []SchnorrSecretKV{kv_1, kv_2, kv_3, kv_4, kv_5})

	// SERVER
	// In response to this each server will generate two
	// arbitrary secrets and respond with a commitment.
	commit1 := SchnorrMGenerateCommitment(suite)
	commit2 := SchnorrMGenerateCommitment(suite)
	commit3 := SchnorrMGenerateCommitment(suite)
	commit4 := SchnorrMGenerateCommitment(suite)
	commit5 := SchnorrMGenerateCommitment(suite)

	// Client side
	commit_array := []SchnorrMPublicCommitment{
		SchnorrMPublicCommitment{commit1.suite, commit1.PublicCommitment().T},
		SchnorrMPublicCommitment{commit2.suite, commit2.PublicCommitment().T},
		SchnorrMPublicCommitment{commit3.suite, commit3.PublicCommitment().T},
		SchnorrMPublicCommitment{commit4.suite, commit4.PublicCommitment().T},
		SchnorrMPublicCommitment{commit5.suite, commit5.PublicCommitment().T}}
	aggregate_commitment := SchnorrMComputeAggregateCommitment(suite,
		commit_array)

	// client and servers
	collective_challenge, err := SchnorrMComputeCollectiveChallenge(suite,
		randomdata, aggregate_commitment)

	if err != nil {
		t.Error("Error during Verification")
		t.Error(err.Error())
	}

	// servers respond to client with responses
	response_1 := SchnorrMUnmarshallCCComputeResponse(suite,
		kv_1, commit1, collective_challenge)
	response_2 := SchnorrMUnmarshallCCComputeResponse(suite,
		kv_2, commit2, collective_challenge)
	response_3 := SchnorrMUnmarshallCCComputeResponse(suite,
		kv_3, commit3, collective_challenge)
	response_4 := SchnorrMUnmarshallCCComputeResponse(suite,
		kv_4, commit4, collective_challenge)
	response_5 := SchnorrMUnmarshallCCComputeResponse(suite,
		kv_5, commit5, collective_challenge)

	// finally, we compute a signature given the responses.
	responsearr := []SchnorrMResponse{response_1, response_2, response_3,
		response_4, response_5}

	sig := SchnorrMComputeSignatureFromResponses(suite, collective_challenge,
		responsearr)

	bsig, err := sig.Encode()
	if err != nil {
		t.Error("Error during Verification")
		t.Error(err.Error())
	}

	verified, err := SchnorrVerify(suite,
		sharedpubkey.GetSchnorrPK(), randomdata, bsig)

	if err != nil {
		t.Error("Error during Verification")
		t.Error(err.Error())
	}
	if verified == false {
		t.Error("Verification of signature failed.")
	}
}
