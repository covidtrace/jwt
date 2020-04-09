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

	claims, err := issuer.Validate(token)
	if err != nil {
		t.Error(err)
	}

	if claims.Hash != "hash" {
		t.Errorf("Unexpected hash: %v", claims.Hash)
	}

	if claims.Refreshed != 0 {
		t.Errorf("Unexpected refresh: %v", claims.Refreshed)
	}
}
