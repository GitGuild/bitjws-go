package bittsign


import crypto          "github.com/ethereum/go-ethereum/crypto"
import ecdsa           "crypto/ecdsa"
import "fmt"
import "bytes"
import "strings"
import "reflect"
import "encoding/json"

//------------------------------------------------------------------------------
// Structural types
//------------------------------------------------------------------------------

type (
	// Signed JWS compact message structure
	SignedMessage struct {
		Header      *Header
		Claims      *ClaimSet
		Signature   string         // Base64 encoded
	}

	// Signed MultiSig JWS JSON structure
	JWSMultiMessage struct {
		Payload     string           `json:"payload"`
		Signatures  []*JWSSignature  `json:"signatures"`
	}

	// A JWS JSON Signature structure
	JWSSignature struct {
		Protected   string           `json:"protected"`
		Signature   string           `json:"signature"`  // Base64 URL encoded
	}
)

//------------------------------------------------------------------------------
// Exported Functions
//------------------------------------------------------------------------------

// Encode a signed message to <header>.<payload>.<signature> compact serialization
func (sns *SignedMessage) EncodeCompactJWS() (string, error) {
	hdr, err := sns.Header.Encode()
	if err != nil {
		return "", err
	}
	clm, err := sns.Claims.Encode()
	if err != nil {
		return "", err
	}
	compact := fmt.Sprintf("%s.%s", hdr, clm)
	sig := Base64URLEncode([]byte(sns.Signature))
	return fmt.Sprintf("%s.%s", compact, sig), nil
}

// Encode a signed multi signature message to JWS JSON format
func (snm *JWSMultiMessage) EncodeJWS() (string, error) {
	jws, err := json.Marshal(snm)
	if err != nil {
		return "", err
	}
	return string(jws), nil
}

// Try to parse a message, signed or multi or return nil
func ParseMessage(s string) (interface{}) {
	if msg := ParseSignedMessage(s); msg != nil {
		return msg
	}
	if msg := ParseMultiSignedMessage(s); msg != nil {
		return msg
	}
	return nil
}

// Try to parse a signed message or return nil
func ParseSignedMessage(compact string) (*SignedMessage) {
	s := strings.Split(compact, ".")
	if len(s) != 3 {
		return nil
	} else {
		hdr, err := DecodeHeader(s[0])
		if err != nil {
			return nil
		}
		clm, err := DecodeClaims(s[1])
		if err != nil {
			return nil
		}
		sig, err := Base64URLDecode(s[2])
		if err != nil {
			return nil
		}
		return &SignedMessage{
			Header: hdr,
			Claims: clm,
			Signature: string(sig),
		}
	}
}

// Try to parse a JWS message or return nil
func ParseMultiSignedMessage(jwsString string) (*JWSMultiMessage) {
	jws := &JWSMultiMessage{}
	err := json.NewDecoder(bytes.NewBuffer([]byte(jwsString))).Decode(jws)
	if err != nil {
		return nil
	}
	return jws
}

// Serialises a message
func Serialize(header *Header, claims *ClaimSet, message string) ([]byte, error) {
	// Serialize the <header>.<claimset>
	hdr, err := header.Encode()
	if err != nil {
		return []byte(""), err
	}

	clm, err := claims.Encode()
	if err != nil {
		return []byte(""), err
	}
	// Serialize the <header>.<claimset> to payload
	compact := fmt.Sprintf("%s.%s", hdr, clm)
	// Serialize with message <header>.<claimset><message> (non-standard if string is not "")
	payload := fmt.Sprintf("%s%s", compact, message)

	// Encode the message according to bitcoin signed messages
	messageHash := EncodeMessageHash([]byte(payload))
	if err != nil {
		return []byte(""), err
	}

	return messageHash, nil
}

// Sign an unsigned single signature claimset without message
func SimpleSign(key *ecdsa.PrivateKey, hdr *Header, clm *ClaimSet) (*SignedMessage, error) {
        return Sign(key, hdr, clm, "")
}

// Sign an unsigned single signature claimset with a message
func Sign(key *ecdsa.PrivateKey, hdr *Header, clm *ClaimSet, message string) (*SignedMessage, error) {
	data, err := Serialize(hdr, clm, message)
	if err != nil {
		return nil, err
	}

	// Sign the message with the private key
	signature, err := crypto.Sign(data, key)
	if err != nil {
		return nil, err
	}

	// Encode the signature to compact / base64
	encoded := EncodeSignature(signature, true)
	if err != nil {
		return nil, err
	}

	return &SignedMessage{
		Header: hdr,
		Claims: clm,
		Signature: encoded,
	}, nil
}

// Sign an unsigned multi-signature request without a body
func SimpleSignMulti(seckeys []*ecdsa.PrivateKey, hdrs []*Header, clm *ClaimSet) (*JWSMultiMessage, error) {
        return SignMulti(seckeys, hdrs, clm, "")
}

// Sign an unsigned multi-signature request with the provided body
func SignMulti(seckeys []*ecdsa.PrivateKey, hdrs []*Header, clm *ClaimSet, message string) (*JWSMultiMessage, error) {
	if len(hdrs) != len(seckeys) {
		return nil, ErrMultiHeadersLength
	}

	var jwsSignatures []*JWSSignature

	headerIndex := 0
	for _, seckey := range(seckeys) {
		header := hdrs[headerIndex]
		headerIndex += 1

		messageSerialized, err := Serialize(header, clm, message)
		if err != nil {
			return nil, err
		}

		signature, err := crypto.Sign(messageSerialized, seckey)
		if err != nil {
			return nil, err
		}

		encodedSignature := EncodeSignature(signature, true)
		if err != nil {
			return nil, err
		}

		encodedHeader, err := header.Encode()
		if err != nil {
			return nil, err
		}

		jwsSignature := &JWSSignature{
			Protected: encodedHeader,
			Signature: Base64URLEncode([]byte(encodedSignature)),
		}

		jwsSignatures = append(jwsSignatures, []*JWSSignature{jwsSignature}...)
	}

	encodedClaims, err := clm.Encode()
	if err != nil {
		return nil, err
	}

	return &JWSMultiMessage{
		Payload: encodedClaims,
		Signatures: jwsSignatures,
	}, nil
}

// Simple single signature verification
func (sm *SignedMessage) SimpleVerify(pubkey *ecdsa.PublicKey) (bool, error) {
        return sm.Verify(pubkey, "")
}

// Combined single signature verification
func (sm *SignedMessage) Verify(pubkey *ecdsa.PublicKey, body string) (bool, error) {
	// Decode the signature
	signature, err := DecodeSignature(sm.Signature)
	if err != nil {
		return false, err
	}

	// Reconstruct the message from the provided body
	message, err := Serialize(sm.Header, sm.Claims, body)

	// Recover the public key from the message <> signature
	recovered, err := crypto.SigToPub(message, signature)
	if err != nil {
		return false, err
	}

	// Verify that the recovered key matches the input public key
	if !reflect.DeepEqual(recovered, pubkey) {
		return false, ErrRecovery
	}

	// Check that the kid is present in the header for integrity protection
	if sm.Header.Kid == "" {
		return false, ErrKidAbsent
	}

	// Verify that the address of the public key matches the kid
	addr := ToAddress(pubkey)
	if addr != sm.Header.Kid {
		return false, ErrKidNoMatch
	}
	
	return true, nil
}

// Simple multi signature verification
func (jm *JWSMultiMessage) SimpleVerify(pubkeys []*ecdsa.PublicKey) (bool, error) {
        return jm.Verify(pubkeys, "")
}

// Combined multi signature verification
func (jm *JWSMultiMessage) Verify(pubkeys []*ecdsa.PublicKey, body string) (bool, error) {
	for k, signature := range(jm.Signatures) {
		// DecodeHeader(signature.Protected) => Header{}		
		header, err := DecodeHeader(signature.Protected)
		if err != nil {
			return false, err
		}

		// DecodeClaims(jm.Payload) => Claims{}
		claims, err := DecodeClaims(jm.Payload)
		if err != nil {
			return false, err
		}

		decodedSignature, err := DecodeSignature(signature.Signature)
		if err != nil {
			return false, err
		}
		
		message, err := Serialize(header, claims, body)
		if err != nil {
			return false, err
		}

		recovered, err := crypto.SigToPub(message, decodedSignature)
		if err != nil {
			return false, err
		}

		if !reflect.DeepEqual(recovered, pubkeys[k]) {
			return false, ErrRecovery
		}

		if header.Kid == "" {
			return false, ErrKidAbsent
		}

		addr := ToAddress(pubkeys[k])
		if addr != header.Kid {
			return false, ErrKidNoMatch
		}
	}
	
	return true, nil
}




