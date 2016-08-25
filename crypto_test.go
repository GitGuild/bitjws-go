package bittsign


import "reflect"
import "testing"


func TestDoubleSha256(t *testing.T) {
	b := []byte("abcd")
	if !reflect.DeepEqual(ShaSha256(b), ShaSha256(b)) {
		t.Fatal("ShaSha must encode identically")
	}
}

