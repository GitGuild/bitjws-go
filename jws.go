package bitjws


import ecdsa               "crypto/ecdsa"
import "fmt"
import "time"
import "bytes"
import "encoding/json"


//------------------------------------------------------------------------------
// Encoding a signed message gives us a base64 encoded triple
// `<header>.<claimset>.<signature>` whereas encoding a multisig message gives
// us back a JSON representation composed of the fields in the MultiSig message.
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// ClaimSet contains information about the JWT signature including the
// permissions being requested (scopes), the target of the token, the issuer,
// the time the token was issued, and the lifetime of the token.
//------------------------------------------------------------------------------

type ClaimSet struct {
	Iss     string `json:"iss"`             // email address of the client_id of the application making the access token request
	Scope   string `json:"scope,omitempty"` // space-delimited list of the permissions the application requests
	Aud     string `json:"aud,omitempty"`             // descriptor of the intended target of the assertion (Optional).
	Exp     int64  `json:"exp"`             // the expiration time of the assertion (seconds since Unix epoch)
	Iat     int64  `json:"iat"`             // the time the assertion was issued (seconds since Unix epoch)
	Typ     string `json:"typ,omitempty"`   // token type (Optional).

	// Email for which the application is requesting delegated access (Optional).
	Sub     string `json:"sub,omitempty"`

	// The old name of Sub. Client keeps setting Prn to be
	// complaint with legacy OAuth 2.0 providers. (Optional)
	Prn     string `json:"prn,omitempty"`

	// The public key corresponding to the private key used in signing
	PubKey  string `json:"pubkey,omitempty"`

	// The public keys corresponding to the private keys used to sign
	PubKeys []string `json:"pubkeys,omitempty"`

        // A generic message expected to be JSON encodable
        Msg     interface{} `json:"msg,omitempty"`
}

func CreateDefaultClaims(pubkey *ecdsa.PublicKey) *ClaimSet {
	return &ClaimSet{
		Iss: "http://www.example.com/",
		PubKey: Base64Encode(FromECDSAPub(pubkey)),
	}
}

func CreateDefaultClaimsMulti(pubkeys []*ecdsa.PublicKey) *ClaimSet {
	var encodedPubKeys []string
	for _, pubkey := range(pubkeys) {
		encodedPubKeys = append(encodedPubKeys, []string{Base64Encode(FromECDSAPub(pubkey))}...)
	}
	return &ClaimSet{
		Iss: "http://www.example.com/",
		PubKeys: encodedPubKeys,
	}
}

func (c *ClaimSet) Encode() (string, error) {
	// Reverting time back for machines whose time is not perfectly in sync.
	// If client machine's time is in the future according
	// to Google servers, an access token will not be issued.
	now := time.Now().Add(-10 * time.Second)
	if c.Iat == 0 {
		c.Iat = now.Unix()
	}
	if c.Exp == 0 {
		c.Exp = now.Add(time.Hour).Unix()
	}
	if c.Exp < c.Iat {
		return "", fmt.Errorf("jws: invalid Exp = %v; must be later than Iat = %v", c.Exp, c.Iat)
	}

	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	return Base64Encode(b), nil
}

// Header represents the header for the signed JWS payload
type Header struct {
	// The algorithm used for signing the payload
	Algorithm string `json:"alg"`

	// The type of token
	Typ       string `json:"typ,omitempty"`

	// The key id of protected header fields
	Kid       string `json:"kid,omitempty"`
}

func CreateDefaultHeader(pubkey *ecdsa.PublicKey) *Header {
	return &Header{
		Algorithm: "CUSTOM-BITCOIN-SIGN",
		Typ: "JWS",
		Kid: ToAddress(pubkey),
	}
}

func (h *Header) Encode() (string, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	return Base64Encode(b), nil
}

// Decodes a JWS header
func DecodeHeader(s string) (*Header, error) {
	hdrBytes, err := Base64Decode(s)
	if err != nil {
		return nil, err
	}		
	hdr := &Header{}
	err = json.NewDecoder(bytes.NewBuffer(hdrBytes)).Decode(hdr)
	if err != nil {
		return nil, err
	}
	return hdr, nil
}

// Decodes a JWS ClaimSet
func DecodeClaims(s string) (*ClaimSet, error) {
	clmBytes, err := Base64Decode(s)
	if err != nil {
		return nil, err
	}
	clm := &ClaimSet{}
	err = json.NewDecoder(bytes.NewBuffer(clmBytes)).Decode(clm)
	if err != nil {
		return nil, err
	}
	return clm, nil
}
