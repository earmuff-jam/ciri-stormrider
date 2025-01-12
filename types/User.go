package types

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type UserCredentials struct {
	ID                uuid.UUID `json:"id,omitempty"`
	Email             string    `json:"email,omitempty"`
	Username          string    `json:"username,omitempty"`
	Birthday          string    `json:"birthday,omitempty"`
	Role              string    `json:"role,omitempty"`
	UserAgent         string    `json:"user_agent,omitempty"`
	EncryptedPassword string    `json:"password,omitempty"`
	PreBuiltToken     string    `json:"pre_token,omitempty"`
	LicenceKey        string    `json:"licence_key,omitempty"`
	ExpirationTime    time.Time `json:"expiration_time,omitempty"`
	jwt.StandardClaims
}
