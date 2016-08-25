package bitjws


import "strings"
import "encoding/base64"


// Extract the first byte from a uint as a bytestring
func ExtractUint8(size uint) ([]byte) {
	u8 := make([]byte, 1)
	u8[0] = byte(size & 0xFF)
	return u8
}

// Extract the first two bytes from a uint as a bytestring
func ExtractUint16(size uint16) ([]byte) {
	var mask uint16 = 0xFF
	u16 := make([]byte, 1+2)
	u16[0] = byte(0xFD)
	i := 1
	for i < 3 {
		u16[i] = byte(size & mask)
		size >>= 8
		i += 1
	}
	return u16
}

// Extract the first four bytes from a uint as a bytetring
func ExtractUint32(size uint32) ([]byte) {
	var mask uint32 = 0xFF
	u32 := make([]byte, 1+4)
	u32[0] = byte(0xFE)
	i := 1
	for i < 5 {
		u32[i] = byte(size & mask)
		size >>= 8
		i += 1
	}
	return u32
}

// Extract the first eight bytes from a uint
func ExtractUint64(size uint64) ([]byte) {
	var mask uint64 = 0xFF
	u64 := make([]byte, 1+8)
	u64[0] = byte(0xFF)
	i := 1
	for i < 9 {
		u64[i] = byte(size & mask)
		size >>= 8
		i += 1
	}
	return u64
}

func Base64URLEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")	
}

func Base64URLDecode(s string) ([]byte, error) {
	// add back missing padding
	switch len(s) % 4 {
	case 1:
		s += "==="
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func Base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// The following is required for WIF functionality at a later date
// Encode the WIF_PREFIX, ideally this should be a constant
//wifPrefix := make([]byte, 1)
//wifPrefix[0] = 0x80
// Encode the PUBKEY_PREFIX, ideally this should be a constant
//pubPrefix := make([]byte, 1)
//pubPrefix[0] = 0x00

