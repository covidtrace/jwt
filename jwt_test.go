package jwt

import (
	"testing"
	"time"
)

var issuer *Issuer

func newIssuer(d string) (*Issuer, error) {
	dur, err := time.ParseDuration(d)
	if err != nil {
		return nil, err
	}

	return NewIssuer([]byte("SIGNING_KEY_HERE"), "iss", "aud", dur), nil
}

func init() {
	var err error
	issuer, err = newIssuer("1h")
	if err != nil {
		panic(err)
	}
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

func TestExpired(t *testing.T) {
	var err error
	issuer, err = newIssuer("1ms")
	if err != nil {
		t.Error(err)
	}

	token, err := issuer.Token("hash", 0)
	if err != nil {
		t.Error(err)
	}

	time.Sleep(1 * time.Second)

	_, err = issuer.Validate(token)
	if err == nil {
		t.Fatalf("Validate should have failed due to expiration")
	}
}

func TestCopy(t *testing.T) {
	var err error
	issuer, err = newIssuer("1ms")
	if err != nil {
		t.Error(err)
	}

	copy := issuer.Copy()
	if copy.iss != issuer.iss {
		t.Errorf("Expected issuers to match: %v, %v", copy.iss, issuer.iss)
	}

	aud := copy.WithAud("new")
	if aud.aud == copy.aud {
		t.Errorf("Expected aud to not match: %v, %v", aud.aud, copy.aud)
	}
}
