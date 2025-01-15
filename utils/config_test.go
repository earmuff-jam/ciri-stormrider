package utils

import (
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func Test_BuildVerificationToken(t *testing.T) {

	durationOfValidity := 15
	baseLicenseKey := string(BASE_LICENSE_KEY)

	customClaims := jwt.StandardClaims{
		ExpiresAt: int64(durationOfValidity),
	}

	resp, err := BuildVerificationToken(customClaims, baseLicenseKey)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp), 20)

}

func Test_RefreshVerificationToken(t *testing.T) {

	durationOfValidity := 15
	baseLicenseKey := string(BASE_LICENSE_KEY)

	customClaims := jwt.StandardClaims{
		ExpiresAt: int64(durationOfValidity),
	}

	resp, err := RefreshVerificationToken(customClaims, baseLicenseKey)

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

	customClaims := jwt.StandardClaims{
		ExpiresAt: int64(durationOfValidity),
	}

	resp, err := RefreshVerificationToken(customClaims, "")

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

	customClaims := jwt.StandardClaims{
		ExpiresAt: int64(durationOfValidity),
	}

	resp, err := RefreshVerificationToken(customClaims, string(BASE_LICENSE_KEY))

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp), 20)

	// parse and validate the claims after receiving it
	token, err := jwt.ParseWithClaims(resp, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(BASE_LICENSE_KEY), nil
	})

	assert.Error(t, err)
	assert.False(t, token.Valid)

}

func Test_ParseJwtToken(t *testing.T) {

	durationOfValidity := 15
	baseLicenseKey := string(BASE_LICENSE_KEY)

	customClaims := jwt.StandardClaims{
		ExpiresAt: int64(durationOfValidity),
		Subject:   "test_user",
	}

	resp, err := BuildVerificationToken(customClaims, baseLicenseKey)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp), 20)

	parsedResp, err := ParseJwtToken(resp, "")
	assert.NoError(t, err)
	assert.Equal(t, parsedResp.Claims.Subject, "test_user")

}

func Test_ParseJwtToken_InvalidDurationOfValidity(t *testing.T) {

	durationOfValidity := -1
	baseLicenseKey := string(BASE_LICENSE_KEY)

	customClaims := jwt.StandardClaims{
		ExpiresAt: int64(durationOfValidity),
		Subject:   "test_user",
	}

	resp, err := BuildVerificationToken(customClaims, baseLicenseKey)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp), 20)

	_, err = ParseJwtToken(resp, "")
	assert.Error(t, err)

}
