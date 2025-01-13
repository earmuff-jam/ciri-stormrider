package stormRider

import (
	"fmt"
	"log"
	"strconv"

	"github.com/dgrijalva/jwt-go"
	"github.com/earmuff-jam/ciri-stormrider/types"
	"github.com/earmuff-jam/ciri-stormrider/utils"
)

// CreateJWT...
//
// Creates JWT token and returns the valid token
// Expiration time: 15 mins ( default )
// BaseKey: Unique UUID used to sign the JWT. If not passed in, default UUID from utils is used.
func CreateJWT(creds *types.Credentials, expiryTime string, baseKey string) (*types.Credentials, error) {

	formattedExpiryTime, err := strconv.ParseInt(expiryTime, 10, 64)
	if err != nil {
		formattedExpiryTime = 15
	}

	if len(baseKey) <= 0 {
		baseKey = string(utils.BASE_LICENSE_KEY)
	}

	jwtTokenString, err := utils.BuildVerificationToken(int(formattedExpiryTime), baseKey)
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
// Refresh the jwt token if it is within 30 seconds of expiry time
func RefreshToken(additionalTime string, baseKey string) (string, error) {

	tokenStr, err := utils.RefreshVerificationToken(additionalTime, baseKey)
	if err != nil {
		log.Printf("unable to refresh token. error %+v", err)
		return "", err
	}

	return tokenStr, nil
}
