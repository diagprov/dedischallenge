package schnorrgs

// These are the unit tests for
// the crypto package. I have tested
// keyset generation, signing and verification only

import (
	"github.com/dedis/kyber/group/edwards25519"
	"testing"
)

func TestSchnorrGenerateKeyset(t *testing.T) {

	suite := edwards25519.NewBlakeSHA256Ed25519()
	_, err := SchnorrGenerateKeypair(suite)
	if err != nil {
		t.Error("Keypair generation failed")
	}
}

func TestSchnorrSignature(t *testing.T) {

	suite := edwards25519.NewBlakeSHA256Ed25519()

	// for good measure, do a few.
	// in proper code we'd not just rely
	// on random generation, we'd also have
	// some known test vectors.
	for i := 0; i < 100; i++ {
		kv, err := SchnorrGenerateKeypair(suite)
		if err != nil {
			t.Error("Keypair generation failed")
		}

		pk := kv.GetPublicKeyset()
		message := []byte("This is a test")
		wrongmessage := []byte("Clearly this shouldn't work")

		sig, err := SchnorrSignBinary(suite, kv, message)
		if err != nil {
			t.Error("Signature Generation failed")
		}

		v1, e1 := SchnorrVerifyBinary(suite, pk, message, sig)
		if e1 != nil {
			t.Error("Error during Verification")
		}
		if v1 == false {
			t.Error("Verification of signature failed")
		}

		v2, e2 := SchnorrVerifyBinary(suite, pk, wrongmessage, sig)
		if e2 != nil {
			t.Error("Error during Verification")
		}
		if v2 == true {
			t.Error("Verification of signature succeeded for bad message")
		}
	}
}

func TestMarshalling(t *testing.T) {

	suite := edwards25519.NewBlakeSHA256Ed25519()
	for i := 0; i < 100; i++ {
		kv, err := SchnorrGenerateKeypair(suite)
		if err != nil {
			t.Error("Keypair generation failed")
			t.Error(err.Error())
		}

		message := []byte("This is a test")

		sig, err := SchnorrSign(suite, kv, message)
		if err != nil {
			t.Error("Signature Generation failed")
		}

		b, err := sig.Encode()
		if err != nil {
			t.Error("Keypair generation failed")
			t.Error(err.Error())
		}

		sig_from_b, err := DecodeSchnorrSignature(suite, b)
		if err != nil {
			t.Error("Keypair generation failed")
			t.Error(err.Error())
		}

		if !sig_from_b.S.Equal(sig.S) {
			t.Error("Signature S values not equal")
		}
		if !sig_from_b.E.Equal(sig.E) {
			t.Error("Signature S values not equal")
		}
	}
}
