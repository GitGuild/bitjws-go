package bittsign


import "fmt"
import "testing"


func TestUint8Encoding(t *testing.T) {
	if fmt.Sprintf("%x", VarInt(0x0F)) != "0f" {
		t.Fatal("Uint8 does not encode according to Bitcoin protocl")
	}
}

func TestUint16Encoding(t *testing.T) {
	if fmt.Sprintf("%x", VarInt(0x0FF0)) != "fdf00f" {
		t.Fatal("Uint16 does not encode according to Bitcoin protocol")
	}
}

func TestUint32Encoding(t *testing.T) {
	if fmt.Sprintf("%x", VarInt(0xFF00FF00)) != "fe00ff00ff" {
		t.Fatal("Uint32 does not encode according to Bitcoin protocol")
	}
}

func TestUint64Encoding(t *testing.T) {
	if fmt.Sprintf("%x", VarInt(0xFE0000FEFE000000)) != "ff000000fefe0000fe" {
		t.Fatal("Uint64 does not encode according to Bitcoin protocol")
	}
}

