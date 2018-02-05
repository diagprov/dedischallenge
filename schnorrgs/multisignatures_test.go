package schnorrgs

import (
	"crypto/rand"
	"github.com/dedis/kyber"
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
	kv1, err := SchnorrGenerateKeypair(suite)
	if err != nil {
		t.Error(err.Error())
	}
	kv2, err := SchnorrGenerateKeypair(suite)
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

	// SERVER: somehow these have been sent to the client.
	pk1 := kv1.GetPublicKeyset()
	pk2 := kv2.GetPublicKeyset()

	// CLIENT: compute combined public key:
	sharedpubkey := SchnorrMSComputeSharedPublicKey(suite,
		[]SchnorrPublicKV{pk1, pk2})

	// SERVERS: generate commitments and send to client:
	commit1 := SchnorrMSGenerateCommitment(suite)
	commit2 := SchnorrMSGenerateCommitment(suite)
	pcommit1 := commit1.GetPublicCommitment()
	pcommit2 := commit2.GetPublicCommitment()

	// CLIENT: Combine server commitments!
	combined_pcommit := SchnorrMSAggregateCommitment(suite,
		[]SchnorrMSPublicCommitment{pcommit1, pcommit2})

	// CLIENT OR SERVER: compute collective challenge based on
	// message:
	collectivechallenge, err := SchnorrMSComputeCollectiveChallenge(suite,
		combined_pcommit, randomdata)
	if err != nil {
		t.Error("Collective challenge computation failed.")
		t.Error(err.Error())
	}

	// SERVERS: compute a response per server:
	r1 := SchnorrMSComputeResponse(suite, collectivechallenge, kv1, commit1)
	r2 := SchnorrMSComputeResponse(suite, collectivechallenge, kv2, commit2)

	// CLIENT: combine the responses:
	r := SchnorrMSComputeCombinedResponse(suite, []kyber.Scalar{r1, r2})
	// CLIENT: make a signature:
	sig := SchnorrMSCreateSignature(suite, collectivechallenge, r)

	verified, err := SchnorrVerify(suite,
		sharedpubkey,
		randomdata, sig)

	if err != nil {
		t.Error("Error during Verification")
		t.Error(err.Error())
	}
	if verified == false {
		t.Error("Verification of signature failed.")
	}
}

func testMultisignatureNServerScenario(t *testing.T, n int) {

	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Generate ourselves two keypairs, one for each "server"

	var privatekeys []SchnorrSecretKV
	var publickeys []SchnorrPublicKV

	for i := 0; i < n; i++ {
		kv, err := SchnorrGenerateKeypair(suite)
		if err != nil {
			t.Error(err.Error())
		}
		privatekeys = append(privatekeys, kv)
		publickeys = append(publickeys, kv.GetPublicKeyset())
	}

	// Make a random message and "send" it to the server
	randomdata := make([]byte, 1024)
	_, err := rand.Read(randomdata)
	if err != nil {
		t.Error(err.Error())
		return
	}

	// CLIENT: compute combined public key:
	sharedpubkey := SchnorrMSComputeSharedPublicKey(suite, publickeys)

	// SERVERS: generate commitments and send to client:
	var commits []SchnorrMSCommitment
	var pcommits []SchnorrMSPublicCommitment
	for i := 0; i < n; i++ {
		commit := SchnorrMSGenerateCommitment(suite)
		commits = append(commits, commit)
		pcommits = append(pcommits, commit.GetPublicCommitment())
	}

	// CLIENT: Combine server commitments!
	combined_pcommit := SchnorrMSAggregateCommitment(suite, pcommits)

	// CLIENT OR SERVER: compute collective challenge based on
	// message:
	collectivechallenge, err := SchnorrMSComputeCollectiveChallenge(suite,
		combined_pcommit, randomdata)
	if err != nil {
		t.Error("Collective challenge computation failed.")
		t.Error(err.Error())
	}

	// SERVERS: compute a response per server:
	var responses []kyber.Scalar
	for i := 0; i < n; i++ {
		resp := SchnorrMSComputeResponse(suite, collectivechallenge,
			privatekeys[i], commits[i])
		responses = append(responses, resp)
	}
	// CLIENT: combine the responses:
	r := SchnorrMSComputeCombinedResponse(suite, responses)
	// CLIENT: make a signature:
	sig := SchnorrMSCreateSignature(suite, collectivechallenge, r)

	verified, err := SchnorrVerify(suite,
		sharedpubkey,
		randomdata, sig)

	if err != nil {
		t.Error("Error during Verification")
		t.Error(err.Error())
	}
	if verified == false {
		t.Error("Verification of signature failed.")
	}
}

func TestMultisignature5ServerScenario(t *testing.T) {
	testMultisignatureNServerScenario(t, 5)
}

func TestMultisignature100ServerScenario(t *testing.T) {
	testMultisignatureNServerScenario(t, 100)
}
