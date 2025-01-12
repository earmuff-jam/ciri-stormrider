package utils

import (
	"log"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var BASE_LICENSE_KEY = []byte("2530d6a4-5d42-4758-b331-2fbbfed27bf9")

// BuildVerificationToken ...
//
// Method is used to build tokens for jwt.
func BuildVerificationToken(durationOfValidity int, baselicenseKey string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Duration(durationOfValidity) * time.Minute).Unix(),
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
func RefreshVerificationToken(additionalTime string, baseKey string) (string, error) {

	draftAdditionalTime, err := strconv.ParseInt(additionalTime, 10, 64)
	if err != nil || draftAdditionalTime <= 0 {
		draftAdditionalTime = 15
	}

	if len(baseKey) <= 0 {
		baseKey = string(BASE_LICENSE_KEY)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Duration(draftAdditionalTime) * time.Minute).Unix(),
	})

	tokenStr, err := token.SignedString([]byte(baseKey))
	if err != nil {
		log.Printf("unable to extend token. error :- %+v", err)
		return "", err
	}
	return tokenStr, nil
}
