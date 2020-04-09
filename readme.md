# covidtrace/jwt

JWT is a simplified wrapper around [jwt-go](https://github.com/dgrijalva/jwt-go)
that is used by COVID Trace for issuing and verifying JWT tokens. Token claims
include a `covidtrace:hash` identifier and a `covidtrace:refreshed` count of the
number of times a token has been refreshed.