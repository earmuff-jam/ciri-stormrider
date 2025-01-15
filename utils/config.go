package utils

import (
	"errors"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/earmuff-jam/ciri-stormrider/types"
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

// ParseJwtToken ...
//
// Parses the provided jwt token and returns the claims
func ParseJwtToken(tokenString string, baseKey string) (*types.Credentials, error) {
	// Use default base key if not provided
	if len(baseKey) == 0 {
		baseKey = string(BASE_LICENSE_KEY)
	}

	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(baseKey), nil
	})

	if err != nil {
		log.Printf("Error parsing token: %v\n", err)
		return nil, err
	}

	// Extract and validate claims
	if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
		credentials := &types.Credentials{
			Claims:     *claims,
			LicenceKey: baseKey,
			Cookie:     tokenString,
		}

		return credentials, nil
	}

	log.Printf("unable to decode passed in jwt. error: %+v", errors.New("invalid claims"))
	return nil, errors.New("invalid claims")
}
