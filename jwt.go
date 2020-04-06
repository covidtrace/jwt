package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type HashClaim struct {
	Hash string `json:"covidtrace:hash"`
	jwt.StandardClaims
}

type Issuer struct {
	sm  jwt.SigningMethod
	key []byte
	iss string
	aud string
	dur time.Duration
}

func NewIssuer(key []byte, iss, aud string, dur time.Duration) *Issuer {
	return &Issuer{sm: jwt.SigningMethodHS256, key: key, iss: iss, aud: aud, dur: dur}
}

func (i *Issuer) Token(hash string) (string, error) {
	t := jwt.NewWithClaims(i.sm, &HashClaim{
		hash,
		jwt.StandardClaims{
			Audience:  i.aud,
			Issuer:    i.iss,
			ExpiresAt: time.Now().Add(i.dur).Unix(),
		},
	})

	return t.SignedString(i.key)
}

func (i *Issuer) Validate(signedString string) (string, error) {
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
		return "", errors.New("Invalid jwt")
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("Invalid jwt")
	}

	if iss, ok := claims["iss"]; !ok || iss.(string) != i.iss {
		return "", fmt.Errorf("Invalid iss: %v", iss)
	}

	if aud, ok := claims["aud"]; !ok || aud.(string) != i.aud {
		return "", fmt.Errorf("Invalid aud: %v", aud)
	}

	hash, ok := claims["covidtrace:hash"]
	if !ok {
		return "", fmt.Errorf("Invalid hash: %v", hash)
	}

	return hash.(string), nil
}
