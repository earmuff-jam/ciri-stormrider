package types

import "github.com/dgrijalva/jwt-go"

// Credentials ...
type Credentials struct {
	Claims     jwt.StandardClaims
	Cookie     string `json:"pre_token,omitempty"`
	LicenceKey string `json:"licence_key,omitempty"`
}
