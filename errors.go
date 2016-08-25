package bitjws

import "errors"

var (
	ErrRecovery = errors.New("Supplied public key is not equal to the key recovered from the signature.")
	ErrKidAbsent = errors.New("No Kid was supplied in the header.")
	ErrKidNoMatch = errors.New("Kid does not match recovered address.")

	ErrMultiHeadersLength = errors.New("The amount of keys is not equal to the amount of JWS headers.")
)
