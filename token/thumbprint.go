package token

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// Thumbprint is the RFC 7638 JWK thumbprint of an Ed25519 public key.
func Thumbprint(publicKey []byte) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("token: install public key must be 32 bytes")
	}
	// Member order is fixed by the struct so the hash input stays canonical.
	body, err := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
	}{
		Crv: "Ed25519",
		Kty: "OKP",
		X:   base64.RawURLEncoding.EncodeToString(publicKey),
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// RequestSigningInput binds a heartbeat body to an instant and an install.
func RequestSigningInput(instanceID string, timestamp time.Time, body []byte) []byte {
	sum := sha256.Sum256(body)
	encoded := base64.RawURLEncoding.EncodeToString(sum[:])
	return []byte(instanceID + "." + itoa(timestamp.Unix()) + "." + encoded)
}

// VerifyRequest checks the install signature on a heartbeat and the skew window.
func VerifyRequest(publicKey ed25519.PublicKey, instanceID string, timestamp time.Time, body, signature []byte, now time.Time, skew time.Duration) error {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return ErrSignature
	}
	delta := now.Sub(timestamp)
	if delta < 0 {
		delta = -delta
	}
	if delta > skew {
		return ErrWindow
	}
	input := RequestSigningInput(instanceID, timestamp, body)
	if !ed25519.Verify(publicKey, input, signature) {
		return ErrSignature
	}
	return nil
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
