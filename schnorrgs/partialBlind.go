package schnorrgs

/*
This file implements the blind signature scheme as described in the given paper.
In particular I would like to note that I have confused terminology a litte
given we are building a server/client architecture. In this case:

1. User/client are interchangeable. These sign the message but do so in a
   partially blind fashion as described.
2. Server/signer are interchangeable. This entity holds private parameters and
   can sign messages
   given agreed information witht he user/client by answering challenges.

Of particular concern in my implementation is the Z-generation. The paper
describes F(info) as a public key with no known private key; in order to
generate a point on the curve we have effectively taken g^{F(info)} which
means F(info) could act as a private key in a schnorr signature scheme. I am
not sure if this breaks the security of the system. However, given some info we
need to deterministically find a curve point, which we cannot do with the
underlying library at present.
*/

import (
	//"bytes"
	"crypto/rand"
	"github.com/dedis/kyber"
	"golang.org/x/crypto/blake2b"
	"io"
)

// Represents he prviate parameters
// generated in Fig 1. "signer"
// You'll also want to use Schnorr.go to generate
// a public/private keypair
type WISchnorrBlindPrivateParams struct {
	U kyber.Scalar
	S kyber.Scalar
	D kyber.Scalar
	Z kyber.Point
	A kyber.Point
	B kyber.Point
}

func (b WISchnorrBlindPrivateParams) MarshalTo(w io.Writer) {
	b.U.MarshalTo(w)
	b.S.MarshalTo(w)
	b.D.MarshalTo(w)
	b.Z.MarshalTo(w)
	b.A.MarshalTo(w)
	b.B.MarshalTo(w)
}

func (b WISchnorrBlindPrivateParams) UnmarshalBinary(raw []byte) {
	b.U.UnmarshalBinary(raw[:b.U.MarshalSize()])
	b.S.UnmarshalBinary(raw[b.U.MarshalSize():b.S.MarshalSize()])
	b.D.UnmarshalBinary(raw[b.S.MarshalSize():b.D.MarshalSize()])
	b.Z.UnmarshalBinary(raw[b.D.MarshalSize():b.Z.MarshalSize()])
	b.A.UnmarshalBinary(raw[b.Z.MarshalSize():b.A.MarshalSize()])
	b.B.UnmarshalBinary(raw[b.A.MarshalSize():b.B.MarshalSize()])
}

/* GenerateZ takes some random agreed information and creates
   Z the "public-only" key that is witness-independent as per
   the paper. We've probably broken that slightly in this implementation
   because I could not pick a point without generating it
   via a Secret, instead of directly via a Point - that is, even as a
   32-byte string, we cannot decode on C25519 (and this wouldn't work
   for CryptoSuites anyway).

   However, it demonstrates the idea.
*/
func GenerateZ(suite CryptoSuite, info []byte) (kyber.Point, error) {

	hasher, _ := blake2b.New512(nil)
	hasher.Write(info)

	zfactor := suite.Scalar().SetBytes(hasher.Sum(nil))
	Z := suite.Point().Mul(zfactor, nil)

	return Z, nil
}

// public parameters that can be transmitted to
// the end-user who wishes to request a signature
// where "transmit" could be embedding in the key
// since there's no requirement for this stage to
// be an online protocol
type WISchnorrPublicParams struct {
	A kyber.Point
	B kyber.Point
}

func (pp WISchnorrPublicParams) MarshalTo(w io.Writer) {
	pp.A.MarshalTo(w)
	pp.B.MarshalTo(w)
}

func (pp WISchnorrPublicParams) UnmarshalBinary(b []byte) {
	pp.A.UnmarshalBinary(b[:pp.A.MarshalSize()])
	pp.B.UnmarshalBinary(b[pp.A.MarshalSize():pp.B.MarshalSize()])
}

/* The challenge message is the structure the user
   generates and passes to the server
   in order for it to be signed.
   This is essentially just E.
*/
type WISchnorrChallengeMessage struct {
	E kyber.Scalar
}

func (cm WISchnorrChallengeMessage) MarshalTo(w io.Writer) {
	cm.E.MarshalTo(w)
}

func (cm WISchnorrChallengeMessage) UnmarshalBinary(b []byte) {

}

// Generates all of the private parameters aside
// from the private / public key pair. Do that
// separately.
func NewPrivateParams(suite CryptoSuite, info []byte) (WISchnorrBlindPrivateParams, error) {

	r1 := make([]byte, 16)
	r2 := make([]byte, 16)
	r3 := make([]byte, 16)

	v := make([]byte, 16)
	_, err := rand.Read(r1)
	if err != nil {
		return WISchnorrBlindPrivateParams{}, err
	}
	_, err = rand.Read(r2)
	if err != nil {
		return WISchnorrBlindPrivateParams{}, err
	}
	_, err = rand.Read(r3)
	if err != nil {
		return WISchnorrBlindPrivateParams{}, err
	}
	_, err = rand.Read(v)
	if err != nil {
		return WISchnorrBlindPrivateParams{}, err
	}

	z, err := GenerateZ(suite, info)
	if err != nil {
		return WISchnorrBlindPrivateParams{}, err
	}

	u := suite.Scalar().SetBytes(r1)
	s := suite.Scalar().SetBytes(r2)
	d := suite.Scalar().SetBytes(r3)

	a := suite.Point().Mul(u, nil)  // g^u
	b1 := suite.Point().Mul(s, nil) // g^s
	b2 := suite.Point().Mul(d, z)   // z^d
	b := suite.Point().Add(b1, b2)  // g^sz^d

	return WISchnorrBlindPrivateParams{u, s, d, z, a, b}, nil
}

// Takes a private parameter "tuple" and extracts from it a
// proper public "tuple"
func (this *WISchnorrBlindPrivateParams) DerivePubParams() WISchnorrPublicParams {
	return WISchnorrPublicParams{this.A, this.B}
}

/* The client parameter list is the structure
   packing all those elements that the client owns
   but does not transmit. */
type WISchnorrClientParamersList struct {
	T1 kyber.Scalar
	T2 kyber.Scalar
	T3 kyber.Scalar
	T4 kyber.Scalar
	Z  kyber.Point
}

/* This function is responsible for producing the challenge message E to send
   back to the signer. */
func ClientGenerateChallenge(suite CryptoSuite,
	publicParameters WISchnorrPublicParams, pk SchnorrPublicKV,
	info []byte, msg []byte) (WISchnorrChallengeMessage,
	WISchnorrClientParamersList, error) {

	r1 := make([]byte, 16)
	r2 := make([]byte, 16)
	r3 := make([]byte, 16)
	r4 := make([]byte, 16)
	_, err := rand.Read(r1)
	if err != nil {
		return WISchnorrChallengeMessage{}, WISchnorrClientParamersList{}, err
	}
	_, err = rand.Read(r2)
	if err != nil {
		return WISchnorrChallengeMessage{}, WISchnorrClientParamersList{}, err
	}
	_, err = rand.Read(r3)
	if err != nil {
		return WISchnorrChallengeMessage{}, WISchnorrClientParamersList{}, err
	}
	_, err = rand.Read(r4)
	if err != nil {
		return WISchnorrChallengeMessage{}, WISchnorrClientParamersList{}, err
	}

	t1 := suite.Scalar().SetBytes(r1)
	t2 := suite.Scalar().SetBytes(r2)
	t3 := suite.Scalar().SetBytes(r3)
	t4 := suite.Scalar().SetBytes(r4)

	z, err := GenerateZ(suite, info)
	if err != nil {
		return WISchnorrChallengeMessage{}, WISchnorrClientParamersList{}, err
	}

	zraw, _ := z.MarshalBinary()

	packedParameters := WISchnorrClientParamersList{t1, t2, t3, t4, z}

	// There might be a better way to lay out this
	// code but it hardly matters.
	// The compiler will be issuing temporary vars
	// all over the show anyway.
	// At least this way I am sure
	// exactly what the code does.

	alpha1 := suite.Point()
	alpha1.Mul(t1, nil)
	alpha := suite.Point()
	alpha.Mul(t2, pk.pP)
	alpha.Add(alpha, alpha1).Add(alpha, publicParameters.A)

	beta1 := suite.Point()
	beta1.Mul(t3, nil)
	beta := suite.Point()
	beta.Mul(t4, z).Add(beta, beta1).Add(beta, publicParameters.B)

	var combinedmsg []byte

	bAlpha, _ := alpha.MarshalBinary()
	bBeta, _ := beta.MarshalBinary()

	//zraw, _ := publicParameters.Z.MarshalBinary()

	combinedmsg = append(combinedmsg, bAlpha...)
	combinedmsg = append(combinedmsg, bBeta...)
	combinedmsg = append(combinedmsg, zraw...)
	combinedmsg = append(combinedmsg, msg...)

	hasher, _ := blake2b.New512(nil)
	hasher.Write(combinedmsg)
	epsilon := suite.Scalar().SetBytes(hasher.Sum(nil))

	e := suite.Scalar()
	e.Sub(epsilon, t2).Sub(e, t4)

	return WISchnorrChallengeMessage{e}, packedParameters, nil
}

/* This is the response message the server sends back to the user */
type WISchnorrResponseMessage struct {
	R kyber.Scalar
	C kyber.Scalar
	S kyber.Scalar
	D kyber.Scalar
}

/* The servergenerateresponse function is fairly self explanatory - this
   function provides an answer to the challenge message provided by the user.*/
func ServerGenerateResponse(suite CryptoSuite, challenge WISchnorrChallengeMessage, privateParameters WISchnorrBlindPrivateParams, privKey SchnorrSecretKV) WISchnorrResponseMessage {

	c := suite.Scalar()
	c.Sub(challenge.E, privateParameters.D)
	r := suite.Scalar()
	r.Mul(c, privKey.s).Sub(privateParameters.U, r)

	return WISchnorrResponseMessage{r, c, privateParameters.S,
		privateParameters.D}
}

/* This structure implements the elements of the blind signature as described
   in the paper They match in order and are designed to "Look like" the greek
   symbols, so P=rho. W = omega, S=sigma, D=delta */
type WIBlindSignature struct {
	P kyber.Scalar
	W kyber.Scalar
	S kyber.Scalar
	D kyber.Scalar
}

/* This is the function that given the client's challenge and response from the
   server is able to compute the final blind signature. This is done on the
   user side (blindly to the signer). */
func ClientSignBlindly(suite CryptoSuite, clientParameters WISchnorrClientParamersList, responseMsg WISchnorrResponseMessage, pubKey SchnorrPublicKV, msg []byte) (WIBlindSignature, bool) {

	rho := suite.Scalar()
	omega := suite.Scalar()
	sigma := suite.Scalar()
	delta := suite.Scalar()

	rho.Add(responseMsg.R, clientParameters.T1)
	omega.Add(responseMsg.C, clientParameters.T2)
	sigma.Add(responseMsg.S, clientParameters.T3)
	delta.Add(responseMsg.D, clientParameters.T4)

	gp := suite.Point()
	gp.Mul(rho, nil)

	yw := suite.Point()
	yw.Mul(omega, pubKey.pP)
	gpyw := suite.Point()

	gpyw.Add(gp, yw)
	bGpyw, _ := gpyw.MarshalBinary()

	gs := suite.Point()
	gs.Mul(sigma, nil)
	zd := suite.Point()
	zd.Mul(delta, clientParameters.Z)
	gszd := suite.Point()
	gszd.Add(gs, zd)
	bGszd, _ := gszd.MarshalBinary()

	bZ, _ := clientParameters.Z.MarshalBinary()

	var combinedmsg []byte

	combinedmsg = append(combinedmsg, bGpyw...)
	combinedmsg = append(combinedmsg, bGszd...)
	combinedmsg = append(combinedmsg, bZ...)
	combinedmsg = append(combinedmsg, msg...)

	hasher, _ := blake2b.New512(nil)
	hasher.Write(combinedmsg)
	sig := suite.Scalar().SetBytes(hasher.Sum(nil))

	vsig := suite.Scalar()
	vsig.Add(omega, delta)

	//fmt.Println(sig)
	//fmt.Println(vsig)

	return WIBlindSignature{rho, omega, sigma, delta}, sig.Equal(vsig)
}

/* This function implements the verification protocol and can be used
   by any party given a decoded schnorr signature, a
   message and valid information. Invalid information will break the protocol
   and produce an invalid message; this is tested for in the unit test code. */
func VerifyBlindSignature(suite CryptoSuite, pk SchnorrPublicKV,
	sig WIBlindSignature, info []byte, msg []byte) (bool, error) {

	z, err := GenerateZ(suite, info)
	if err != nil {
		return false, err
	}

	gp := suite.Point().Mul(sig.P, nil)
	yw := suite.Point().Mul(sig.W, pk.pP)
	gpyw := suite.Point().Add(gp, yw)

	gs := suite.Point().Mul(sig.S, nil)
	zd := suite.Point().Mul(sig.D, z)
	gszd := suite.Point().Add(gs, zd)

	bP1, _ := gpyw.MarshalBinary()
	bP2, _ := gszd.MarshalBinary()
	bZ, _ := z.MarshalBinary()

	var combinedmsg []byte

	combinedmsg = append(combinedmsg, bP1...)
	combinedmsg = append(combinedmsg, bP2...)
	combinedmsg = append(combinedmsg, bZ...)
	combinedmsg = append(combinedmsg, msg...)

	hasher, _ := blake2b.New512(nil)
	hasher.Write(combinedmsg)
	bSig := hasher.Sum(nil)

	hsig := suite.Scalar().SetBytes(bSig)

	vsig := suite.Scalar()
	vsig.Add(sig.W, sig.D)

	return hsig.Equal(vsig), nil
}
