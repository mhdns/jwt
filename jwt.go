package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Payload is used to encode data into a jwt token
type Payload struct {
	Expiry      string
	PayloadTime time.Time
	Exp         int
	Data        interface{}
}

// EncodeOPTS allows user to set the algorithm and type of the JWT
type EncodeOPTS struct {
	Alg  string
	Type string
}

// Base64Encode takes in a string and returns a base 64 encoded string
func Base64Encode(str string) string {
	return strings.
		TrimRight(base64.URLEncoding.
			EncodeToString([]byte(str)), "=")
}

// Base64Decode takes a base64 encoded string and returns an actual string, if it fails it returns an error
func Base64Decode(str string) (string, error) {
	if x := len(str) % 4; x > 0 {
		str += strings.Repeat("=", 4-x)
	}

	decoded, err := base64.URLEncoding.DecodeString(str)
	if err != nil {
		return "", fmt.Errorf("decoding error: %v", err)
	}

	return string(decoded), nil
}

// Hash generates a Hmac256 hash of a string using a secret
func Hash(str string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)

	h.Write([]byte(str))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// isValidHash validates a hash againt a value
func isValidHash(value string, hash string, secret string) bool {
	return hash == Hash(value, secret)
}

// Encode generates a jwt.
func Encode(payload Payload, secret string, opts *EncodeOPTS) string {
	type Header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}

	alg := opts.Alg
	if opts.Alg == "" {
		alg = "HS256"
	}

	typ := opts.Type
	if opts.Type == "" {
		typ = "JWT"
	}

	header := Header{
		Alg: alg,
		Typ: typ,
	}

	str, _ := json.Marshal(header)
	headerString := Base64Encode(string(str))
	encodedPayload, _ := json.Marshal(payload)
	signatureValue := headerString + "." + Base64Encode(string(encodedPayload))
	return signatureValue + "." + Hash(signatureValue, secret)
}

// Decode returns a payload from a valid JWT token, else it returns an error
func Decode(jwt string, secret string) (interface{}, error) {
	token := strings.Split(jwt, ".")
	// check if the jwt token contains
	// header, payload and token
	if len(token) != 3 {
		splitErr := errors.New("Invalid token: token should contain header, payload and secret")
		return nil, splitErr
	}
	// decode payload
	decodedPayload, PayloadErr := Base64Decode(token[1])
	if PayloadErr != nil {
		return nil, fmt.Errorf("Invalid payload: %s", PayloadErr.Error())
	}
	payload := Payload{}
	// parses payload from string to a struct
	ParseErr := json.Unmarshal([]byte(decodedPayload), &payload)
	if ParseErr != nil {
		return nil, fmt.Errorf("Invalid payload: %s", ParseErr.Error())
	}
	// checks if the token has expired.
	if payload.Exp != 0 && time.Now().Before(payload.PayloadTime.Add(time.Second*time.Duration(payload.Exp*1000))) {
		return nil, errors.New("Expired token: token has expired")
	}
	signatureValue := token[0] + "." + token[1]
	// verifies if the header and signature is exactly whats in
	// the signature
	if isValidHash(signatureValue, token[2], secret) == false {
		return nil, errors.New("Invalid token")
	}
	return payload, nil
}
