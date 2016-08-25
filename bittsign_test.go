package bittsign

//------------------------------------------------------------------------------
// Imports
//------------------------------------------------------------------------------

import ecdsa               "crypto/ecdsa"
import crypto              "github.com/ethereum/go-ethereum/crypto"
import "testing"

//------------------------------------------------------------------------------
// Utility
//------------------------------------------------------------------------------

func checkErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

//------------------------------------------------------------------------------
// Fixtures
//------------------------------------------------------------------------------

func jwsCompactParams(t *testing.T) (*Header, *ClaimSet) {
	seckey, err := crypto.HexToECDSA("2934473d31f55a8a7c031bdef35b9587b40249969211aca5c29925cb04f84ccc")
	checkErr(t, err)

	hdr := CreateDefaultHeader(&seckey.PublicKey)
	clm := CreateDefaultClaims(&seckey.PublicKey)

	return hdr, clm
}

func jwsMultiParams(t *testing.T) ([]*Header, *ClaimSet, []*ecdsa.PrivateKey, []*ecdsa.PublicKey) {
	seckey1, err := crypto.GenerateKey()
	checkErr(t, err)
	seckey2, err := crypto.GenerateKey()
	checkErr(t, err)	
	seckey3, err := crypto.GenerateKey()
	checkErr(t, err)	

	hdr1 := CreateDefaultHeader(&seckey1.PublicKey)
	hdr2 := CreateDefaultHeader(&seckey2.PublicKey)
	hdr3 := CreateDefaultHeader(&seckey3.PublicKey)

	clm := CreateDefaultClaimsMulti([]*ecdsa.PublicKey{
		&seckey1.PublicKey,
		&seckey2.PublicKey,
		&seckey3.PublicKey,
	})

	seckeys := []*ecdsa.PrivateKey{ seckey1, seckey2, seckey3 }
	pubkeys := []*ecdsa.PublicKey{
		&seckey1.PublicKey,
		&seckey2.PublicKey,
		&seckey3.PublicKey,
	}

	return []*Header{hdr1, hdr2, hdr3}, clm, seckeys, pubkeys
}

func TestSigning(t *testing.T) {
	seckey, err := crypto.HexToECDSA("2934473d31f55a8a7c031bdef35b9587b40249969211aca5c29925cb04f84ccc")
	checkErr(t, err)

	t.Logf("Private key length: %v", len(crypto.FromECDSA(seckey)))
	t.Logf("private key: %x", crypto.FromECDSA(seckey))
	t.Logf("public key: %x", crypto.FromECDSAPub(&seckey.PublicKey))
	
	hdr, clm := jwsCompactParams(t)

	// Signed compact representation
	sm, err := Sign(seckey, hdr, clm, "foo")
	checkErr(t, err)

	_, err = sm.EncodeCompactJWS() // smc
	checkErr(t, err)

	r1, err := Base64Decode(sm.Signature)
	checkErr(t, err)

	t.Logf("Signature length == %v", len(r1))

	if len(r1) != 65 {
		t.Fatal("Invalid signature length")
	}

	res, err := sm.Verify(&seckey.PublicKey, "foo")
	checkErr(t, err)

	if err != nil || res == false {
		t.Fatal("Failed to recover a public key from signature")
	}
}

// func TestMulti(t *testing.T) {
// 	hdrs, clm, signMap, verifyMap := multiSignatureFixtures(t)
// 	unm := unsignedMultiFixtures(t, hdrs, clm)

// 	reqBody := []byte("{type: 'some type'}")
	
// 	snm, err := unm.SignMultiRequest(signMap, reqBody)
// 	checkErr(t, err)

// 	_, err = snm.VerifyRecoverRequest(reqBody)
// 	checkErr(t, err)

// 	valid, err := snm.ValidateRequest(verifyMap, reqBody)
// 	checkErr(t, err)

// 	v2, err := snm.VerifyRequest(verifyMap, reqBody)

// 	if valid != true {
// 		t.Fatal("Verification of keymap failed")
// 	}
// 	if v2 != true {
// 		t.Fatal("Verification + Validation failed")
// 	}

// 	enc, err := snm.ToJWS()
// 	checkErr(t, err)

// 	t.Logf("enc: %v", enc)
// }

