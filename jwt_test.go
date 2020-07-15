package jwt

import (
	"log"
	"testing"
	"time"
)

func TestHash(t *testing.T) {
	if Hash("Anas", "secret") != "00hebHHzZ1LSaaPKmxRRpkHqJmh437WlErW+SgRZopw=" {
		t.Errorf("hash generated is not correct: recieved: %v", Hash("Anas", "secret"))
	}
}

func TestEncode(t *testing.T) {
	payload := Payload{
		Exp:         300,
		PayloadTime: time.Now(),
		Data: struct {
			Name string
			Age  int
		}{
			Name: "Anas",
			Age:  27,
		},
	}

	log.Print(Encode(payload, "secret", &EncodeOPTS{}))
}

func TestDecode(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJQYXlsb2FkVGltZSI6IjIwMjAtMDctMTVUMTQ6NTM6NDkuMzIyMjk0KzA4OjAwIiwiRXhwIjozMDAsIkRhdGEiOnsiTmFtZSI6IkFuYXMiLCJBZ2UiOjI3fX0.mSRglTwTyFj02lRyli/dthhnegunjEsWUp+jqPQASj8="
	log.Print(Decode(token, "secret"))
}
