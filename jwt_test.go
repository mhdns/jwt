package jwt

import (
	"testing"
)

func TestHash(t *testing.T) {
	if Hash("Anas", "secret") != "00hebHHzZ1LSaaPKmxRRpkHqJmh437WlErW+SgRZopw=" {
		t.Errorf("hash generated is not correct: recieved: %v", Hash("Anas", "secret"))
	}
}
