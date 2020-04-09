package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type hashClaim struct {
	Hash      string `json:"covidtrace:hash"`
	Refreshed int    `json:"covidtrace:refreshed"`
	jwt.StandardClaims
}

// Issuer is the core covidtrace/jwt type. It exposes methods to issue and
// verify tokens.
type Issuer struct {
	sm  jwt.SigningMethod
	key []byte
	iss string
	aud string
	dur time.Duration
}

// NewIssuer returns, well, a new `Issuer`
func NewIssuer(key []byte, iss, aud string, dur time.Duration) *Issuer {
	return &Issuer{sm: jwt.SigningMethodHS256, key: key, iss: iss, aud: aud, dur: dur}
}

// Token handles generating a signed JWT token with the given `hash` and
// `refresh` count
func (i *Issuer) Token(hash string, refresh int) (string, error) {
	t := jwt.NewWithClaims(i.sm, &hashClaim{
		hash,
		refresh,
		jwt.StandardClaims{
			Audience:  i.aud,
			Issuer:    i.iss,
			ExpiresAt: time.Now().Add(i.dur).Unix(),
		},
	})

	return t.SignedString(i.key)
}

// Validate handles ensuring `signedString` is a valid JWT issued by this
// issuer. It returns the `hash` and `refreshed` claims, or an `error` if the
// token is invalid
func (i *Issuer) Validate(signedString string) (string, int, error) {
	t, err := jwt.Parse(signedString, func(t *jwt.Token) (interface{}, error) {
		if t == nil {
			return nil, errors.New("Token is nil")
		}

		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
		}

		return i.key, nil
	})

	if err != nil || t == nil || !t.Valid {
		return "", -1, errors.New("Invalid jwt")
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return "", -1, errors.New("Invalid jwt")
	}

	if iss, ok := claims["iss"]; !ok || iss.(string) != i.iss {
		return "", -1, fmt.Errorf("Invalid iss: %v", iss)
	}

	if aud, ok := claims["aud"]; !ok || aud.(string) != i.aud {
		return "", -1, fmt.Errorf("Invalid aud: %v", aud)
	}

	hash, ok := claims["covidtrace:hash"]
	if !ok {
		return "", -1, fmt.Errorf("Invalid hash: %v", hash)
	}

	refreshed, ok := claims["covidtrace:refreshed"]
	if !ok {
		refreshed = 0
	}

	refresh, ok := refreshed.(float64)
	if !ok {
		refresh, ok := refreshed.(int)
		if !ok {
			return "", -1, fmt.Errorf("Invalid refresh: %v", refresh)
		}
	}

	return hash.(string), int(refresh), nil
}
