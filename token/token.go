// Package token is the signed-snapshot contract. The control plane and the
// install library both import it. It cannot reach a database or a signing key.
package token

import "crypto/ed25519"

const (
	SchemaV1 = "monarch.token.v1"

	Issuer     = "monarch"
	RootIssuer = "monarch-root"

	TypToken      = "monarch-token+jwt"
	TypDelegation = "monarch-delegation+jwt"

	DeliveryHeartbeat = "heartbeat"
	DeliveryFile      = "file"

	EnforcementAllow = "allow"
	EnforcementDeny  = "deny"

	AllowSignToken = "sign-token"
)

// Claims is the payload of a license snapshot. The signature covers the raw
// JSON bytes; callers must not re-marshal a token in order to check it.
type Claims struct {
	Schema           string       `json:"schema"`
	Issuer           string       `json:"iss"`
	Audience         string       `json:"aud"`
	Subject          string       `json:"sub"`
	Org              string       `json:"org"`
	License          string       `json:"lic"`
	Version          int64        `json:"ver"`
	Delivery         string       `json:"delivery"`
	Enforcement      string       `json:"enforcement"`
	Reason           string       `json:"reason,omitempty"`
	IssuedAt         int64        `json:"iat"`
	NotBefore        int64        `json:"nbf"`
	ExpiresAt        int64        `json:"exp"`
	LicenseExpiresAt int64        `json:"license_exp"`
	GraceSeconds     int64        `json:"grace"`
	Confirmation     Confirmation `json:"cnf"`
	Entitlements     Entitlements `json:"entitlements"`
	Config           Config       `json:"config"`
	NextCheckin      int64        `json:"next_checkin"`
	Environment      string       `json:"env"`
	JTI              string       `json:"jti"`
}

// Confirmation binds a snapshot to one install public key (RFC 7638 thumbprint).
type Confirmation struct {
	Thumbprint string `json:"jkt"`
}

// Entitlements is the only place a feature is granted.
type Entitlements struct {
	Features map[string]bool  `json:"features"`
	Limits   map[string]int64 `json:"limits"`
}

// Config is the compiled runtime document sealed into the same snapshot.
type Config struct {
	Revision int64          `json:"revision"`
	Schema   string         `json:"schema"`
	Values   map[string]any `json:"values"`
}

// Delegation is the offline master's authorization for one issuing key.
// The issuing key signs tokens. It cannot authorize another issuing key.
type Delegation struct {
	Issuer      string   `json:"iss"`
	Subject     string   `json:"sub"`
	PublicKey   []byte   `json:"pub"`
	Environment string   `json:"env"`
	Allow       []string `json:"allow"`
	NotBefore   int64    `json:"nbf"`
	ExpiresAt   int64    `json:"exp"`
}

// Signed is what the agent receives. Delegation travels with the token so an
// install that only has the master public key can still chain verification.
type Signed struct {
	Token      string `json:"token"`
	Delegation string `json:"delegation"`
}

// Masters maps a master key id to the pinned Ed25519 public key.
type Masters map[string]ed25519.PublicKey
