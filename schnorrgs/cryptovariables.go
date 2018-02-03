package schnorrgs

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"golang.org/x/crypto/blake2b"
	//	"github.com/dedis/kyber/group/nist"
	"strings"
)

// This represents the suite of parameters used
// in a given instantiation of any of the Schnorr Algorithsm
type CryptoSuite interface {
	kyber.Group
	kyber.Random
}

// This function computes H(r||M) in the cryptosuite using the blake2b
// hash function for mapping back to the scalar types.
func SchnorrHashPointsMsgToScalar(k CryptoSuite, R kyber.Point,
	msg []byte) (kyber.Scalar, error) {
	h, err := blake2b.New512(nil)
	if err != nil {
		return nil, err
	}

	_, err = R.MarshalTo(h)
	if err != nil {
		return nil, err
	}
	_, err = h.Write(msg)
	if err != nil {
		return nil, err
	}

	return k.Scalar().SetBytes(h.Sum(nil)), nil
}

func GetSuite(suite string) (CryptoSuite, error) {
	if suite == "BlakeSHA256Ed25519" {
		return edwards25519.NewBlakeSHA256Ed25519(), nil
		// this should, but doesn't work.
		//	} else if suite == "BlakeSHA256P256" {
		//		return nist.
	} else {
		return nil, errors.New("Invalid cipher suite specified.")
	}
}

// Represents a Schnorr Secret keyset.
type SchnorrSecretKV struct {
	suite string       // identifier for the suite used.
	s     kyber.Scalar // Secret key, represented as a kyber scalar type.
	pP    kyber.Point  // public key represented as an encoded byte                              // string of the given point.
}

// Represents only the public key
// from a given keypair. Caps notation is not used for points as this
// automatically makes them public.
type SchnorrPublicKV struct {
	suite string      // identifier for the suite used
	pP    kyber.Point // Public key represent as an encoded byte string
}

type SchnorrSecretDiskRepr struct {
	Suite string
	S     string
	P     string
}

func (s SchnorrSecretKV) GetPublicKeyset() SchnorrPublicKV {
	return SchnorrPublicKV{suite: s.suite, pP: s.pP}
}

func (k SchnorrSecretKV) Export() []byte {

	bins := k.s.Bytes()
	strs := hex.EncodeToString(bins)

	diskrepr := SchnorrSecretDiskRepr{
		Suite: k.suite,
		S:     strs,
		P:     k.pP.String(),
	}

	b, _ := json.Marshal(diskrepr)

	return b
}

func NewSchnorrSecretKVFromImport(source []byte) (*SchnorrSecretKV, error) {

	var umkv SchnorrSecretDiskRepr

	// Unmarshall into above struct:
	err := json.Unmarshal(source, &umkv)
	if err != nil {
		return nil, err
	}

	// Now try to construct a SchnorrSecretKV:
	suite, err := GetSuite(umkv.Suite)
	if err != nil {
		return nil, err
	}

	decodedbin_s, err := hex.DecodeString(umkv.S)
	if err != nil {
		return nil, err
	}

	decodedbin_p, err := hex.DecodeString(umkv.P)
	if err != nil {
		return nil, err
	}

	var unmashalledScalar = suite.Scalar()
	err = unmashalledScalar.UnmarshalBinary(decodedbin_s)
	if err != nil {
		return nil, err
	}

	var unmashalledPoint = suite.Point()
	err = unmashalledPoint.UnmarshalBinary(decodedbin_p)
	if err != nil {
		return nil, err
	}

	return &SchnorrSecretKV{
		suite: umkv.Suite,
		s:     unmashalledScalar,
		pP:    unmashalledPoint,
	}, nil
}

func (p SchnorrPublicKV) Export() string {
	// No JSON for this, let's save ourselves the effort
	return p.suite + ";" + p.pP.String()
}

func NewSchnorrPublicKeyFromString(source string) (*SchnorrPublicKV, error) {
	splitsource := strings.Split(source, ";")
	suiteid := splitsource[0]
	encodedp := splitsource[1]

	suite, err := GetSuite(suiteid)
	if err != nil {
		return nil, err
	}

	decodedbin_p, err := hex.DecodeString(encodedp)
	if err != nil {
		return nil, err
	}

	var unmarshalledPoint = suite.Point()
	err = unmarshalledPoint.UnmarshalBinary(decodedbin_p)

	if err != nil {
		return nil, err
	}

	result := SchnorrPublicKV{
		suite: suiteid,
		pP:    unmarshalledPoint,
	}

	return &result, nil
}
