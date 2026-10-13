package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// ParseMasters reads comma-separated kid:base64url public keys.
func ParseMasters(spec string) (Masters, error) {
	out := Masters{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kid, encoded, ok := strings.Cut(part, ":")
		if !ok || kid == "" {
			return nil, fmt.Errorf("master key %q", part)
		}
		if _, exists := out[kid]; exists {
			return nil, fmt.Errorf("duplicate master key %s", kid)
		}
		pub, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("master public key %s", kid)
		}
		out[kid] = ed25519.PublicKey(pub)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no master keys")
	}
	return out, nil
}
