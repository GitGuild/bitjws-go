package bitjws


import ecdsa             "crypto/ecdsa"
import "github.com/gorilla/context"
import "io/ioutil"
import "net/http"
import "strings"
import "errors"
import "fmt"


//------------------------------------------------------------------------------
// Middleware
//------------------------------------------------------------------------------

// A function called whenever an error is encountered
func OnError(w http.ResponseWriter, r *http.Request, err string) {
	http.Error(w, err, http.StatusUnauthorized)
}

// DSA adapter interface
type DSAAdapter interface {
        // Implement registration of a pubkey
        Register(pubkey *ecdsa.PublicKey) (interface{}, error)
        // Implement fetch a registered key
        GetRegisteredKey(pubkey *ecdsa.PublicKey) (interface{}, error)
}

// The state stored within this handler
type SigningMiddleware struct {
	// This services private key
	SecKey *ecdsa.PrivateKey
	// The DSA configuration
	DSA *DSAAdapter
}

func New(seckey *ecdsa.PrivateKey, db *DSAAdapter) *SigningMiddleware {
	return &SigningMiddleware{ 
		SecKey: seckey,
		DSA: db,
	}
}

//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

// Negroni specific middleware handler
func (m *SigningMiddleware) HandlerWithNext(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	err := m.Verify(w, r)
	
	if err == nil && next != nil {
		next(w, r)
	}
}

// net.http middleware handler
func (m *SigningMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := m.Verify(w, r)

		if err != nil {
			return
		}

		h.ServeHTTP(w, r)
	})
}

// Verify the JWS message
func (m *SigningMiddleware) Verify(w http.ResponseWriter, r *http.Request) error {
	// Decode the request body, this could be anything but in a GET request
	// is expected to be []byte("")
	jwsMessage, _ := ioutil.ReadAll(r.Body)

	// Parse the message into a signed {header, claimset, sig}
	// TODO: Cater for multi-signed messages
	signed := ParseMessage(jwsMessage)
	if signed == nil {
		err := errors.New("Message must be a valid Bitcoin JWS serialisation")
		OnError(w, r, err.Error())
		return err
	}

	pubkeybytes, err := Base64Decode(signed.Claims.PubKey)
	pubkey := ToECDSAPub(pubkeybytes)
	
	// Lookup public key in DSA
	key, err := m.DSA.GetRegisteredKey(pubkey, &m.SecKey.PublicKey)
	if err != nil {
		// User is not registered, fail to authorize
		OnError(w, r, err.Error())
		return fmt.Errorf("Error: %v\n", err)
	}

	// User is registered, check the signature against the request body
	res, err := signed.SimpleVerify(&m.SecKey.PublicKey)
	if err != nil {
		// An error occured during signature verification
		OnError(w, r, err.Error())
		return fmt.Errorf("Error: %v", err)
	}
	if res == false {
		// Signature didn't match expected
		err = errors.New("Signature verification failed")
		OnError(w, r, err.Error())
		return fmt.Errorf("Error: %v", err)
	}

	// Message is valid, add public key to request context
	context.Set(r, "public_key", key)

	return nil
}


