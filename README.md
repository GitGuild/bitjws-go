# bitjws-go
Go library for bitjws authentication, signing and verification.

### This is a placehodler for a work in progress. For working examples, see:

[Python bitjws](https://github.com/deginner/bitjws)
[Javascript bitjws](https://github.com/deginner/bitjws-js)

## How To Use

    import bitjws "github.com/GitGuild/bitjws-go"

    // Generate a secret key (libsecp256k1)
    seckey, err := bitjws.GenerateKey()
    if err != nil {
            return nil, err
    }
    
    // Create a jws Header which contains your header
    header := &bitjws.Header{
            Algorithm: "CUSTOM-BITCOIN-SIGN",
	    Typ: "JWS",
	    Kid: bitjws.ToAddress(&seckey.PublicKey),
    }

    // Create a set of claims
    claims := &bitjws.ClaimSet{
            Iss: "http://www.example.com",
	    ...
    }

    // Sign the header / claimset
    signedMessage, err := SimpleSign(seckey, header, claims)
    if err != nil {
            return nil, err
    }

    // Encode the signed message into compact JWS format
    compact, err := signedMessage.EncodeCompactJWS()
    if err != nil {
            return nil, err
    }

    // Verify a signed message
    checkSig, err := signedMessage.Verify(&seckey.PublicKey)
    if err != nil {
            return nil, err
    }

