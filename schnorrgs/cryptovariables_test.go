package schnorrgs

import (
	"testing"
)

func TestSuiteInstantiation(t *testing.T) {

	_, err := GetSuite("BlakeSHA256Ed25519")
	if err != nil {
		t.Fatalf("BlakeSHA256Ed25519 instantiation failed.")
	}

	//	nist, err := GetSuite("BlakeSHA256P256")
	//	if err != nil {
	//		t.Fatalf("BlakeSHA256P256 instantiation failed.")
	//	}

	_, err = GetSuite("SEsgYXJlIGtub2JzLg==")
	if err == nil {
		t.Fatalf("Got a valid suite when passing junk.")
	}
}
