package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrMalformed     = errors.New("token: malformed jws")
	ErrAlgorithm     = errors.New("token: algorithm is not EdDSA")
	ErrSignature     = errors.New("token: signature mismatch")
	ErrUnknownMaster = errors.New("token: unknown master key")
	ErrDelegationUse = errors.New("token: delegation cannot sign tokens")
	ErrKeyMismatch   = errors.New("token: signing key does not match delegation")
	ErrThumbprint    = errors.New("token: install key does not match confirmation")
	ErrWindow        = errors.New("token: outside validity window")
	ErrInvalidClaims = errors.New("token: claims rejected")
)

type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// HeaderJSON returns the protected header. Struct order keeps the bytes stable.
// Verification never switches cryptographic algorithm based on this field:
// every signature is checked as Ed25519, and any other alg is rejected.
func HeaderJSON(typ, kid string) ([]byte, error) {
	if typ == "" || kid == "" {
		return nil, ErrMalformed
	}
	return json.Marshal(jwsHeader{Alg: "EdDSA", Kid: kid, Typ: typ})
}

// SigningInput is the exact ASCII string the private key must sign.
func SigningInput(headerJSON, payload []byte) string {
	return b64(headerJSON) + "." + b64(payload)
}

// Complete appends a raw Ed25519 signature to a signing input.
func Complete(signingInput string, signature []byte) string {
	return signingInput + "." + b64(signature)
}

func b64(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func splitCompact(compact string) (header, payload, signature string, err error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", ErrMalformed
	}
	return parts[0], parts[1], parts[2], nil
}

func verifySegment(pub ed25519.PublicKey, headerPart, payloadPart, signaturePart string) ([]byte, jwsHeader, error) {
	sig, err := base64.RawURLEncoding.DecodeString(signaturePart)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, jwsHeader{}, ErrMalformed
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerPart)
	if err != nil {
		return nil, jwsHeader{}, ErrMalformed
	}
	var header jwsHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, jwsHeader{}, ErrMalformed
	}
	if header.Alg != "EdDSA" {
		return nil, jwsHeader{}, ErrAlgorithm
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return nil, jwsHeader{}, ErrMalformed
	}
	if !ed25519.Verify(pub, []byte(headerPart+"."+payloadPart), sig) {
		return nil, jwsHeader{}, ErrSignature
	}
	return rawPayload, header, nil
}

// VerifyDelegation checks a master-signed issuing-key authorization.
func VerifyDelegation(compact string, masters Masters, now time.Time) (Delegation, error) {
	headerPart, payloadPart, signaturePart, err := splitCompact(compact)
	if err != nil {
		return Delegation{}, err
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerPart)
	if err != nil {
		return Delegation{}, ErrMalformed
	}
	var peek jwsHeader
	if err := json.Unmarshal(headerJSON, &peek); err != nil {
		return Delegation{}, ErrMalformed
	}
	pub, ok := masters[peek.Kid]
	if !ok {
		return Delegation{}, ErrUnknownMaster
	}
	raw, header, err := verifySegment(pub, headerPart, payloadPart, signaturePart)
	if err != nil {
		return Delegation{}, err
	}
	if header.Typ != TypDelegation {
		return Delegation{}, ErrMalformed
	}
	var delegation Delegation
	if err := json.Unmarshal(raw, &delegation); err != nil {
		return Delegation{}, ErrMalformed
	}
	if err := validateDelegation(delegation, now); err != nil {
		return Delegation{}, err
	}
	return delegation, nil
}

func validateDelegation(d Delegation, now time.Time) error {
	if d.Issuer != RootIssuer || d.Subject == "" || d.Environment == "" {
		return fmt.Errorf("%w: delegation identity", ErrInvalidClaims)
	}
	if len(d.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: issuing key", ErrInvalidClaims)
	}
	if !allows(d, AllowSignToken) {
		return ErrDelegationUse
	}
	if len(d.Allow) != 1 {
		return ErrDelegationUse
	}
	nowU := now.Unix()
	if nowU < d.NotBefore || nowU >= d.ExpiresAt {
		return ErrWindow
	}
	return nil
}

func allows(d Delegation, use string) bool {
	for _, item := range d.Allow {
		if item == use {
			return true
		}
	}
	return false
}

// Verify checks a snapshot against a pinned master and the install public key.
func Verify(tokenCompact, delegationCompact string, masters Masters, now time.Time, instancePublicKey ed25519.PublicKey) (Claims, error) {
	delegation, err := VerifyDelegation(delegationCompact, masters, now)
	if err != nil {
		return Claims{}, err
	}
	claims, err := verifyToken(tokenCompact, delegation)
	if err != nil {
		return Claims{}, err
	}
	if err := ValidateSigning(claims, delegation, now); err != nil {
		return Claims{}, err
	}
	thumb, err := Thumbprint(instancePublicKey)
	if err != nil {
		return Claims{}, err
	}
	if subtleConst(thumb, claims.Confirmation.Thumbprint) == false {
		return Claims{}, ErrThumbprint
	}
	return claims, nil
}

func subtleConst(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range len(a) {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func verifyToken(compact string, delegation Delegation) (Claims, error) {
	headerPart, payloadPart, signaturePart, err := splitCompact(compact)
	if err != nil {
		return Claims{}, err
	}
	raw, header, err := verifySegment(ed25519.PublicKey(delegation.PublicKey), headerPart, payloadPart, signaturePart)
	if err != nil {
		return Claims{}, err
	}
	if header.Typ != TypToken {
		return Claims{}, ErrMalformed
	}
	if header.Kid != delegation.Subject {
		return Claims{}, ErrKeyMismatch
	}
	var claims Claims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return Claims{}, ErrMalformed
	}
	return claims, nil
}
