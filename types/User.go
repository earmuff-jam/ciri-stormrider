package types

// Credentials ...
type Credentials struct {
	Cookie     string `json:"pre_token,omitempty"`
	LicenceKey string `json:"licence_key,omitempty"`
}
