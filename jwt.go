package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Claims represents the JWT claims covidtrace cares about
type Claims struct {
	Hash       string `json:"covidtrace:hash,omitempty"`
	Identifier string `json:"covidtrace:identifier,omitempty"`
	Refreshed  int    `json:"covidtrace:refreshed"`
	Role       string `json:"covidtrace:role,omitempty"`
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

// Copy returns a copy of `Issuer`
func (i *Issuer) Copy() *Issuer {
	return &Issuer{
		sm:  i.sm,
		key: i.key,
		iss: i.iss,
		aud: i.aud,
		dur: i.dur,
	}
}

// WithAud returns a copy of `Issuer` with `aud` overwritten
func (i *Issuer) WithAud(aud string) *Issuer {
	copy := i.Copy()
	i.aud = aud
	return copy
}

// WithDur returns a copy of `Issuer` with `dur` overwritten
func (i *Issuer) WithDur(dur time.Duration) *Issuer {
	copy := i.Copy()
	i.dur = dur
	return copy
}

// Claims constructs a new Claims object, filling details in from i
func (i *Issuer) Claims(hash string, refresh int, identifier, role string) *Claims {
	return &Claims{
		Hash:       hash,
		Identifier: identifier,
		Refreshed:  refresh,
		Role:       role,
		StandardClaims: jwt.StandardClaims{
			Audience:  i.aud,
			Issuer:    i.iss,
			ExpiresAt: time.Now().Add(i.dur).Unix(),
		},
	}
}

// Token handles generating a signed JWT token with the given `hash` and
// `refresh` count
func (i *Issuer) Token(hash string, refresh int, identifier, role string) (string, error) {
	t := jwt.NewWithClaims(i.sm, i.Claims(hash, refresh, identifier, role))
	return t.SignedString(i.key)
}

func getClaimString(claims jwt.MapClaims, key, def string) string {
	result := def
	if iface, ok := claims[key]; ok {
		if str, ok := iface.(string); ok {
			result = str
		}
	}
	return result
}

func getClaimFloat64(claims jwt.MapClaims, key string, def float64) float64 {
	result := def

	iface, ok := claims["covidtrace:refreshed"]
	if !ok {
		iface = def
	}

	if flt, ok := iface.(float64); ok {
		result = flt
	}

	return result
}

// Validate handles ensuring `signedString` is a valid JWT issued by this
// issuer. It returns the `hash` and `refreshed` claims, or an `error` if the
// token is invalid
func (i *Issuer) Validate(signedString string) (*Claims, error) {
	t, err := jwt.Parse(signedString, func(t *jwt.Token) (interface{}, error) {
		if t == nil {
			return nil, errors.New("Token is nil")
		}

		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
		}

		return i.key, nil
	})

	if err != nil {
		return nil, err
	}

	if t == nil || !t.Valid {
		return nil, errors.New("Invalid jwt")
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("Invalid jwt claims")
	}

	if iss, ok := claims["iss"]; !ok {
		return nil, errors.New("Missing iss")
	} else if iss, ok = iss.(string); !ok || iss != i.iss {
		return nil, fmt.Errorf("Invalid iss: %v", iss)
	}

	if aud, ok := claims["aud"]; !ok {
		return nil, errors.New("Missing aud")
	} else if aud, ok = aud.(string); !ok || aud != i.aud {
		return nil, fmt.Errorf("Invalid aud: %v", aud)
	}

	return i.Claims(
		getClaimString(claims, "covidtrace:hash", ""),
		int(getClaimFloat64(claims, "covidtrace:refresh", 0)),
		getClaimString(claims, "covidtrace:identifier", ""),
		getClaimString(claims, "covidtrace:role", ""),
	), nil
}
