package stormRider

import (
	"strconv"
	"testing"

	"github.com/earmuff-jam/ciri-stormrider/types"
	"github.com/earmuff-jam/ciri-stormrider/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func Test_CreateJWT_DefaultToken(t *testing.T) {

	draftUserCredentials := types.Credentials{}

	resp, err := CreateJWT(&draftUserCredentials, "", "")
	assert.NoError(t, err)
	assert.Equal(t, resp.LicenceKey, string(utils.BASE_LICENSE_KEY))
	assert.GreaterOrEqual(t, len(resp.Cookie), 20)
}

func Test_CreateJWT_CustomToken(t *testing.T) {

	draftTestUUID := uuid.New().String()
	draftUserCredentials := types.Credentials{}

	resp, err := CreateJWT(&draftUserCredentials, "5", draftTestUUID)
	assert.NoError(t, err)
	assert.Equal(t, resp.LicenceKey, draftTestUUID)
	assert.GreaterOrEqual(t, len(resp.Cookie), 20)
}

func Test_TestValidateJWT(t *testing.T) {
	draftTestUUID := uuid.New().String()
	draftUserCredentials := types.Credentials{}

	resp, err := CreateJWT(&draftUserCredentials, "5", draftTestUUID)
	assert.NoError(t, err)
	assert.Equal(t, resp.LicenceKey, draftTestUUID)

	respBool, err := ValidateJWT(resp.Cookie, draftTestUUID)
	assert.NoError(t, err)
	assert.True(t, respBool)
}

func Test_TestValidateJWT_InvalidTokenStr(t *testing.T) {

	resp, err := ValidateJWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzY3MDg0MzN9.OVRtmmns1IuJKcN1pGuQw31KcvWLDZ-LWCIYcrOhKI8PASS", "")

	assert.Error(t, err)
	assert.False(t, resp)
}

func Test_RefreshToken(t *testing.T) {

	tokenStr, err := RefreshToken(strconv.Itoa(15), string(utils.BASE_LICENSE_KEY))

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(tokenStr), 20)
}
