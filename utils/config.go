package utils

import (
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var BASE_LICENSE_KEY = []byte("2530d6a4-5d42-4758-b331-2fbbfed27bf9")

// BuildVerificationToken ...
//
// Method is used to build tokens for jwt.
func BuildVerificationToken(claims jwt.StandardClaims, baselicenseKey string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Id:        claims.Audience,
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		IssuedAt:  claims.IssuedAt,
		Audience:  claims.Audience,
		ExpiresAt: time.Now().Add(time.Duration(claims.ExpiresAt) * time.Minute).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(baselicenseKey))
	if err != nil {
		log.Printf("unable to decode token. error: %+v", err)
		return "", err
	}
	return tokenStr, nil
}

// RefreshVerificationToken...
//
// Method is used to refresh the jwt token
func RefreshVerificationToken(claims jwt.StandardClaims, baseKey string) (string, error) {

	if len(baseKey) <= 0 {
		baseKey = string(BASE_LICENSE_KEY)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Id:        claims.Audience,
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		IssuedAt:  claims.IssuedAt,
		Audience:  claims.Audience,
		ExpiresAt: time.Now().Add(time.Duration(claims.ExpiresAt) * time.Minute).Unix(),
	})

	tokenStr, err := token.SignedString([]byte(baseKey))
	if err != nil {
		log.Printf("unable to extend token. error :- %+v", err)
		return "", err
	}
	return tokenStr, nil
}
