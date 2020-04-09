package jwt

import (
	"testing"
	"time"
)

var issuer *Issuer

func init() {
	dur, err := time.ParseDuration("1h")
	if err != nil {
		panic(err)
	}

	issuer = NewIssuer([]byte("SIGNING_KEY_HERE"), "iss", "aud", dur)
}

func TestIssuer(t *testing.T) {
	token, err := issuer.Token("hash", 0)
	if err != nil {
		t.Error(err)
	}

	hash, refresh, err := issuer.Validate(token)
	if err != nil {
		t.Error(err)
	}

	if hash != "hash" {
		t.Errorf("Unexpected hash: %v", hash)
	}

	if refresh != 0 {
		t.Errorf("Unexpected refresh: %v", refresh)
	}
}
