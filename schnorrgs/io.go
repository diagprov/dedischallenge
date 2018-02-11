package schnorrgs

import (
	"io/ioutil"
	"os"
)

// Loads the key pair as a binary blob from a file on disk
func SchnorrLoadSecretKV(path string) (*SchnorrSecretKV,
	error) {

	fcontents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	kv, err := NewSchnorrSecretKVFromImport(fcontents)

	return kv, err
}

// Saves the keypair as a binary blob on disk. The file format
// matches abstract.Write(...) so whatever that uses, we're using here.
func SchnorrSaveSecretKV(path string, kv SchnorrSecretKV) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	binkey := kv.Export()
	_, err = f.Write(binkey)
	return err
}

// Loads only the public key from disk.
func SchnorrLoadPubkey(path string) (*SchnorrPublicKV,
	error) {

	fcontents, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}
	s := string(fcontents)
	kv, err := NewSchnorrPublicKeyFromString(s)

	return kv, err
}

// Saves only the public key to disk.
func SchnorrSavePubkey(path string, k SchnorrPublicKV) error {
	buf := []byte(k.Export())
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(buf)
	return err
}
