package utils

import (
	"strconv"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func Test_BuildVerificationToken(t *testing.T) {

	durationOfValidity := 15
	baseLicenseKey := string(BASE_LICENSE_KEY)

	resp, err := BuildVerificationToken(durationOfValidity, baseLicenseKey)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp), 20)

	token, err := jwt.ParseWithClaims(resp, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(baseLicenseKey), nil
	})

	assert.NoError(t, err)
	assert.True(t, token.Valid)

}
func Test_RefreshVerificationToken(t *testing.T) {

	durationOfValidity := 15
	baseLicenseKey := string(BASE_LICENSE_KEY)

	resp, err := RefreshVerificationToken(strconv.Itoa(durationOfValidity), baseLicenseKey)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp), 20)

	// parse and validate the claims after receiving it
	token, err := jwt.ParseWithClaims(resp, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(baseLicenseKey), nil
	})

	assert.NoError(t, err)
	assert.True(t, token.Valid)

}

func Test_RefreshVerificationToken_WithCustomToken(t *testing.T) {

	durationOfValidity := 15

	resp, err := RefreshVerificationToken(strconv.Itoa(durationOfValidity), "")

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp), 20)

	// parse and validate the claims after receiving it
	token, err := jwt.ParseWithClaims(resp, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(BASE_LICENSE_KEY), nil
	})

	assert.NoError(t, err)
	assert.True(t, token.Valid)

}

func Test_RefreshVerificationToken_WithNegativeDurationOfValidity(t *testing.T) {

	durationOfValidity := -1

	resp, err := RefreshVerificationToken(strconv.Itoa(durationOfValidity), string(BASE_LICENSE_KEY))

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp), 20)

	// parse and validate the claims after receiving it
	token, err := jwt.ParseWithClaims(resp, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(BASE_LICENSE_KEY), nil
	})

	assert.NoError(t, err)
	assert.True(t, token.Valid)

}
