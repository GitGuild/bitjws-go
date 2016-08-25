package bittsign


import ecdsa              "crypto/ecdsa"
import crypto             "github.com/ethereum/go-ethereum/crypto"
import sha256             "crypto/sha256"
import ripemd160          "golang.org/x/crypto/ripemd160"
import "math/big"
import "strings"
import "bytes"
import "fmt"


//------------------------------------------------------------------------------
// Re-exports from go-ethereum
//------------------------------------------------------------------------------

// Generate a keypair and encode as base64
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

// Convert hex to an ecdsa.PrivateKey
func HexToECDSA(hexstring string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(hexstring)
}

// Convert an ecdsa.PrivateKey to a bytestring
func FromECDSA(seckey *ecdsa.PrivateKey) []byte {
	return crypto.FromECDSA(seckey)
}

// Convert a set of bytes to an ecdsa.PrivateKey
func ToECDSA(b []byte) *ecdsa.PrivateKey {
	return crypto.ToECDSA(b)
}

// Convert an ecdsa.PublicKey to a bytestring
func FromECDSAPub(pubkey *ecdsa.PublicKey) []byte {
	return crypto.FromECDSAPub(pubkey)
}

// Convert a set of bytes to an ecdsa.PublicKey
func ToECDSAPub(b []byte) *ecdsa.PublicKey {
	return crypto.ToECDSAPub(b)
}

//------------------------------------------------------------------------------
// Cryptographic Functions
//------------------------------------------------------------------------------

// Double SHA256 a series of bytes
func ShaSha256(b []byte) []byte {
	hasher := sha256.New()
	hasher.Write(b)
	sha := hasher.Sum(nil)
	hasher.Reset()
	hasher.Write(sha)
	return hasher.Sum(nil)
}

// Ripemd + SHA256 a series of bytes
func Sha256RipeMD160(b []byte) []byte {
	ripe := ripemd160.New()
	sha := sha256.New()
	sha.Write(b)
	ripe.Write(sha.Sum(nil))
	return ripe.Sum(nil)
}

//------------------------------------------------------------------------------
// Base58 Encoding / Decoding
//------------------------------------------------------------------------------

// b58encode encodes a byte slice b into a base-58 encoded string.
func b58encode(b []byte) (s string) {
	/* See https://en.bitcoin.it/wiki/Base58Check_encoding */

	const BITCOIN_BASE58_TABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	/* Convert big endian bytes to big int */
	x := new(big.Int).SetBytes(b)

	/* Initialize */
	r := new(big.Int)
	m := big.NewInt(58)
	zero := big.NewInt(0)
	s = ""

	/* Convert big int to string */
	for x.Cmp(zero) > 0 {
		/* x, r = (x / 58, x % 58) */
		x.QuoRem(x, m, r)
		/* Prepend ASCII character */
		s = string(BITCOIN_BASE58_TABLE[r.Int64()]) + s
	}

	return s
}

// b58decode decodes a base-58 encoded string into a byte slice b.
func b58decode(s string) (b []byte, err error) {
	/* See https://en.bitcoin.it/wiki/Base58Check_encoding */

	const BITCOIN_BASE58_TABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	/* Initialize */
	x := big.NewInt(0)
	m := big.NewInt(58)

	/* Convert string to big int */
	for i := 0; i < len(s); i++ {
		b58index := strings.IndexByte(BITCOIN_BASE58_TABLE, s[i])
		if b58index == -1 {
			return nil, fmt.Errorf("Invalid base-58 character encountered: '%c', index %d.", s[i], i)
		}
		b58value := big.NewInt(int64(b58index))
		x.Mul(x, m)
		x.Add(x, b58value)
	}

	/* Convert big int to big endian bytes */
	b = x.Bytes()

	return b, nil
}

//------------------------------------------------------------------------------
// Base58 Check Encode / Decode 
//------------------------------------------------------------------------------

// b58checkencode encodes version ver and byte slice b into a base-58 check encoded string.
func b58checkencode(ver uint8, b []byte) (s string) {
	/* Prepend version */
	bcpy := append([]byte{ver}, b...)

	/* Create a new SHA256 context */
	sha256_h := sha256.New()

	/* SHA256 Hash #1 */
	sha256_h.Reset()
	sha256_h.Write(bcpy)
	hash1 := sha256_h.Sum(nil)

	/* SHA256 Hash #2 */
	sha256_h.Reset()
	sha256_h.Write(hash1)
	hash2 := sha256_h.Sum(nil)

	/* Append first four bytes of hash */
	bcpy = append(bcpy, hash2[0:4]...)

	/* Encode base58 string */
	s = b58encode(bcpy)

	/* For number of leading 0's in bytes, prepend 1 */
	for _, v := range bcpy {
		if v != 0 {
			break
		}
		s = "1" + s
	}

	return s
}

// b58checkdecode decodes base-58 check encoded string s into a version ver and byte slice b.
func b58checkdecode(s string) (ver uint8, b []byte, err error) {
	/* Decode base58 string */
	b, err = b58decode(s)
	if err != nil {
		return 0, nil, err
	}

	/* Add leading zero bytes */
	for i := 0; i < len(s); i++ {
		if s[i] != '1' {
			break
		}
		b = append([]byte{0x00}, b...)
	}

	/* Verify checksum */
	if len(b) < 5 {
		return 0, nil, fmt.Errorf("Invalid base-58 check string: missing checksum.")
	}

	/* Create a new SHA256 context */
	sha256_h := sha256.New()

	/* SHA256 Hash #1 */
	sha256_h.Reset()
	sha256_h.Write(b[:len(b)-4])
	hash1 := sha256_h.Sum(nil)

	/* SHA256 Hash #2 */
	sha256_h.Reset()
	sha256_h.Write(hash1)
	hash2 := sha256_h.Sum(nil)

	/* Compare checksum */
	if bytes.Compare(hash2[0:4], b[len(b)-4:]) != 0 {
		return 0, nil, fmt.Errorf("Invalid base-58 check string: invalid checksum.")
	}

	/* Strip checksum bytes */
	b = b[:len(b)-4]

	/* Extract and strip version */
	ver = b[0]
	b = b[1:]

	return ver, b, nil
}

//------------------------------------------------------------------------------
// Bitcoin Private Key Import / Export 
//------------------------------------------------------------------------------

// CheckWIF checks that string wif is a valid Wallet Import Format or Wallet Import Format Compressed string. If it is not, err is populated with the reason.
func CheckWIF(wif string) (valid bool, err error) {
	/* See https://en.bitcoin.it/wiki/Wallet_import_format */

	/* Base58 Check Decode the WIF string */
	ver, priv_bytes, err := b58checkdecode(wif)
	if err != nil {
		return false, err
	}

	/* Check that the version byte is 0x80 */
	if ver != 0x80 {
		return false, fmt.Errorf("Invalid WIF version 0x%02x, expected 0x80.", ver)
	}

	/* Check that private key bytes length is 32 or 33 */
	if len(priv_bytes) != 32 && len(priv_bytes) != 33 {
		return false, fmt.Errorf("Invalid private key bytes length %d, expected 32 or 33.", len(priv_bytes))
	}

	/* If the private key bytes length is 33, check that suffix byte is 0x01 (for compression) */
	if len(priv_bytes) == 33 && priv_bytes[len(priv_bytes)-1] != 0x01 {
		return false, fmt.Errorf("Invalid private key bytes, unknown suffix byte 0x%02x.", priv_bytes[len(priv_bytes)-1])
	}

	return true, nil
}

//------------------------------------------------------------------------------
// Bitcoin Public Key Import / Export 
//------------------------------------------------------------------------------

// ToBytes converts a Bitcoin public key to a 33-byte byte slice with point compression.
func ToBytes(pub *ecdsa.PublicKey) (b []byte) {
	/* See Certicom SEC1 2.3.3, pg. 10 */

	x := pub.X.Bytes()

	/* Pad X to 32-bytes */
	padded_x := append(bytes.Repeat([]byte{0x00}, 32-len(x)), x...)

	/* Add prefix 0x02 or 0x03 depending on ylsb */
	if pub.Y.Bit(0) == 0 {
		return append([]byte{0x02}, padded_x...)
	}

	return append([]byte{0x03}, padded_x...)
}

// ToBytesUncompressed converts a Bitcoin public key to a 65-byte byte slice without point compression.
func ToBytesUncompressed(pub *ecdsa.PublicKey) (b []byte) {
	/* See Certicom SEC1 2.3.3, pg. 10 */

	x := pub.X.Bytes()
	y := pub.Y.Bytes()

	/* Pad X and Y coordinate bytes to 32-bytes */
	padded_x := append(bytes.Repeat([]byte{0x00}, 32-len(x)), x...)
	padded_y := append(bytes.Repeat([]byte{0x00}, 32-len(y)), y...)

	/* Add prefix 0x04 for uncompressed coordinates */
	return append([]byte{0x04}, append(padded_x, padded_y...)...)
}

// FromBytes converts a byte slice (either with or without point compression) to a Bitcoin public key.
// func FromBytes(pub *ecdsa.PublicKey, b []byte) (err error) {
// 	/* See Certicom SEC1 2.3.4, pg. 11 */

// 	if len(b) < 33 {
// 		return fmt.Errorf("Invalid public key bytes length %d, expected at least 33.", len(b))
// 	}

// 	if b[0] == 0x02 || b[0] == 0x03 {
// 		/* Compressed public key */

// 		if len(b) != 33 {
// 			return fmt.Errorf("Invalid public key bytes length %d, expected 33.", len(b))
// 		}

// 		P, err := secp256k1.Decompress(new(big.Int).SetBytes(b[1:33]), uint(b[0]&0x1))
// 		if err != nil {
// 			return fmt.Errorf("Invalid compressed public key bytes, decompression error: %v", err)
// 		}

// 		pub.X = P.X
// 		pub.Y = P.Y

// 	} else if b[0] == 0x04 {
// 		/* Uncompressed public key */

// 		if len(b) != 65 {
// 			return fmt.Errorf("Invalid public key bytes length %d, expected 65.", len(b))
// 		}

// 		pub.X = new(big.Int).SetBytes(b[1:33])
// 		pub.Y = new(big.Int).SetBytes(b[33:65])

// 		/* Check that the point is on the curve */
// 		if !secp256k1.IsOnCurve(pub.Point) {
// 			return fmt.Errorf("Invalid public key bytes: point not on curve.")
// 		}

// 	} else {
// 		return fmt.Errorf("Invalid public key prefix byte 0x%02x, expected 0x02, 0x03, or 0x04.", b[0])
// 	}

// 	return nil
// }

// ToAddress converts a Bitcoin public key to a compressed Bitcoin address string.
func ToAddress(pub *ecdsa.PublicKey) (address string) {
	/* See https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses */

	/* Convert the public key to bytes */
	pub_bytes := ToBytes(pub)

	/* SHA256 Hash */
	sha256_h := sha256.New()
	sha256_h.Reset()
	sha256_h.Write(pub_bytes)
	pub_hash_1 := sha256_h.Sum(nil)

	/* RIPEMD-160 Hash */
	ripemd160_h := ripemd160.New()
	ripemd160_h.Reset()
	ripemd160_h.Write(pub_hash_1)
	pub_hash_2 := ripemd160_h.Sum(nil)

	/* Convert hash bytes to base58 check encoded sequence */
	address = b58checkencode(0x00, pub_hash_2)

	return address
}

// ToAddressUncompressed converts a Bitcoin public key to an uncompressed Bitcoin address string.
func ToAddressUncompressed(pub *ecdsa.PublicKey) (address string) {
	/* See https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses */

	/* Convert the public key to bytes */
	pub_bytes := ToBytesUncompressed(pub)

	/* SHA256 Hash */
	sha256_h := sha256.New()
	sha256_h.Reset()
	sha256_h.Write(pub_bytes)
	pub_hash_1 := sha256_h.Sum(nil)

	/* RIPEMD-160 Hash */
	ripemd160_h := ripemd160.New()
	ripemd160_h.Reset()
	ripemd160_h.Write(pub_hash_1)
	pub_hash_2 := ripemd160_h.Sum(nil)

	/* Convert hash bytes to base58 check encoded sequence */
	address = b58checkencode(0x00, pub_hash_2)

	return address
}
