package stormRider

import (
	"fmt"
	"log"

	"github.com/dgrijalva/jwt-go"
	"github.com/earmuff-jam/ciri-stormrider/types"
	"github.com/earmuff-jam/ciri-stormrider/utils"
)

// CreateJWT...
//
// Creates JWT token and returns the valid token
// BaseKey: Unique UUID used to sign the JWT. If not passed in, default UUID from utils is used.
func CreateJWT(creds *types.Credentials, baseKey string) (*types.Credentials, error) {

	if len(baseKey) <= 0 {
		baseKey = string(utils.BASE_LICENSE_KEY)
	}

	jwtTokenString, err := utils.BuildVerificationToken(creds.Claims, baseKey)
	if err != nil {
		log.Printf("unable to create jwt verification token. error: %+v", err)
		return nil, err
	}
	creds.LicenceKey = string(baseKey)
	creds.Cookie = jwtTokenString

	return creds, nil
}

// ValidateJWT...
//
// Validate the cookie by parsing the JWT and the baseLicenseKey
// If the client wants to use a custom license key, they can do such by passing in the
// fields baseLicenseKey. Note, that this requires the client to persist the license key
// on their own terms.
func ValidateJWT(cookie string, baseLicenseKey string) (bool, error) {

	if len(baseLicenseKey) <= 0 {
		baseLicenseKey = string(utils.BASE_LICENSE_KEY)
	}
	token, err := jwt.Parse(cookie, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid license detected")
		}
		return []byte(baseLicenseKey), nil
	})

	if !(token.Valid) {
		log.Printf("invalid token detected. error :%+v", err)
		return false, err
	}

	return true, nil
}

// RefreshToken ...
//
// Refresh the jwt token and returns the valid token
// BaseKey: Unique UUID used to sign the JWT. If not passed in, default UUID from utils is used.
func RefreshToken(creds *types.Credentials, baseKey string) (string, error) {

	tokenStr, err := utils.RefreshVerificationToken(creds.Claims, baseKey)
	if err != nil {
		log.Printf("unable to refresh token. error %+v", err)
		return "", err
	}

	return tokenStr, nil
}

// ParseJwtToken ...
//
// Parse the provided jwt token and return the credentials
// BaseKey: Unique UUID used to sign the JWT. If not passed in, default UUID from utils is used.
func ParseJwtToken(token, baseKey string) (*types.Credentials, error) {

	creds, err := utils.ParseJwtToken(token, baseKey)
	if err != nil {
		log.Printf("unable to parse provided jwt token. error: %+v", err)
		return nil, err
	}
	return creds, nil
}
