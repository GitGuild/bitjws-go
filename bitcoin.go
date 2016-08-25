package bittsign

import ecdsa              "crypto/ecdsa"
import crypto             "github.com/ethereum/go-ethereum/crypto"
import "reflect"

const (
	NETWORK_NAME = "bitcoin"
)

// Sign libsecp256k1
func BitcoinSign(msg []byte, key *ecdsa.PrivateKey) (string, error) {
	hmsg := EncodeMessageHash(msg)
	sig, err := crypto.Sign(hmsg, key)
	if err != nil {
		return "", err
	}
	return EncodeSignature(sig, true), nil
}

// Verify libsecp256k1
func BitcoinVerify(msg []byte, sig string, key *ecdsa.PublicKey) (bool, error) {
	hmsg := EncodeMessageHash(msg)	
	sigbytes, err := DecodeSignature(sig)
	if err != nil {
		return false, err
	}
	// Recover the public key from the msg + signature
	recoveredkey, err := crypto.SigToPub(hmsg, sigbytes)
	if err != nil {
		return false, err
	}
	// If the recovered key is the key we expect, the signature is valid
	if reflect.DeepEqual(key, recoveredkey) {
		return true, nil
	}
	// The key is valid but is not the one we expect
	return false, nil
}

// Encodes a message according to the Bitcoin protocol
func EncodeMessage(payload []byte) ([]byte) {
	msgprefix := []byte("Bitcoin Signed Message:\n")
	msgprefixlen := uint(len(msgprefix))
	paylen := uint(len(payload))
	payprefix := append(VarInt(msgprefixlen), msgprefix...)
	paybody := append(VarInt(paylen), payload...)
	return append(payprefix, paybody...)
}

// Decodes a message encoded for the Bitcoin protocol
// func DecodeMessage(message []byte) ([]byte) { }

// Encodes the message and returns the message digest
func EncodeMessageHash(payload []byte) ([]byte) {
	bs := EncodeMessage(payload)
	hs := ShaSha256(bs)
	return hs[:]
}

// Encodes a series of bytes representing as a Bitcoin compliant signature
func EncodeSignature(sig []byte, compressed bool) (string) {
	var meta byte
	var recid byte
	var sigbytes []byte
	recid = sig[64]
	sigbytes = sig[0:64]
	meta = 27 + recid
	if compressed {
		meta += 4
	}
	sigHdr := make([]byte, 1)
	sigHdr[0] = meta
	return Base64Encode(append(sigHdr, sigbytes...))
}

// Decodes a base64 encoded Bitcoin signature as bytes
func DecodeSignature(encodedSig string) ([]byte, error) {
	sigbytes, err := Base64Decode(encodedSig)

	if err != nil {
		return nil, err
	}

	// Extracts the compressed bits from the first byte in the signature
	// compressed := (sigbytes[0] - 27) & 4 != 0

	// Extracts the recovery id from the first byte in the signature
	recid := make([]byte, 1)
	recid[0] = (sigbytes[0] - 27) & 3
	if err != nil {
		return []byte(""), err
	}

	// remove the header from the message & add recid back
	sig := append(sigbytes[1:], recid...)
	return sig, nil
}

// Performs variable length integer encoding (see BIP)
func VarInt(size uint) ([]byte) {
	if size < 0xFD {
		return ExtractUint8(size)
	} else if size <= 0xFFFF {
		return ExtractUint16(uint16(size))
	} else if size <= 0xFFFFFFFF {
		return ExtractUint32(uint32(size))
	} else {
		return ExtractUint64(uint64(size))
	}
}
