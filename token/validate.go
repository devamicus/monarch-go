package token

import (
	"fmt"
	"time"
)

// ValidateSigning checks the structural rules the signer enforces before an
// issuing key is used. Business rules such as seat counts are applied earlier,
// by the use case that built the claims.
func ValidateSigning(claims Claims, delegation Delegation, now time.Time) error {
	if err := validateDelegation(delegation, now); err != nil {
		return err
	}
	if claims.Schema != SchemaV1 || claims.Issuer != Issuer {
		return fmt.Errorf("%w: schema", ErrInvalidClaims)
	}
	if claims.Audience == "" || claims.Subject == "" || claims.Org == "" || claims.License == "" || claims.JTI == "" {
		return fmt.Errorf("%w: identity", ErrInvalidClaims)
	}
	if claims.Version <= 0 || claims.Environment == "" || claims.Environment != delegation.Environment {
		return fmt.Errorf("%w: version or environment", ErrInvalidClaims)
	}
	if claims.Confirmation.Thumbprint == "" || claims.Config.Schema == "" {
		return fmt.Errorf("%w: confirmation or config", ErrInvalidClaims)
	}
	if claims.NotBefore > claims.IssuedAt || claims.ExpiresAt <= claims.IssuedAt {
		return fmt.Errorf("%w: time order", ErrInvalidClaims)
	}
	if claims.ExpiresAt > delegation.ExpiresAt {
		return fmt.Errorf("%w: outlives issuing key", ErrWindow)
	}
	if now.Unix() >= claims.ExpiresAt || now.Unix() < claims.NotBefore {
		return ErrWindow
	}
	switch claims.Enforcement {
	case EnforcementAllow:
		if claims.Reason != "" {
			return fmt.Errorf("%w: reason on allow", ErrInvalidClaims)
		}
		if claims.LicenseExpiresAt < claims.ExpiresAt {
			return fmt.Errorf("%w: token outlives license", ErrWindow)
		}
	case EnforcementDeny:
		if claims.Reason == "" {
			return fmt.Errorf("%w: deny reason", ErrInvalidClaims)
		}
		if granted(claims.Entitlements) {
			return fmt.Errorf("%w: deny still grants", ErrInvalidClaims)
		}
	default:
		return fmt.Errorf("%w: enforcement", ErrInvalidClaims)
	}
	switch claims.Delivery {
	case DeliveryHeartbeat:
		if claims.GraceSeconds <= 0 || claims.NextCheckin <= 0 {
			return fmt.Errorf("%w: heartbeat schedule", ErrInvalidClaims)
		}
		if claims.ExpiresAt-claims.IssuedAt > claims.GraceSeconds {
			return fmt.Errorf("%w: heartbeat longer than grace", ErrWindow)
		}
	case DeliveryFile:
		if claims.GraceSeconds != 0 || claims.NextCheckin != 0 {
			return fmt.Errorf("%w: file delivery has no grace loop", ErrInvalidClaims)
		}
	default:
		return fmt.Errorf("%w: delivery", ErrInvalidClaims)
	}
	return nil
}

func granted(e Entitlements) bool {
	for _, on := range e.Features {
		if on {
			return true
		}
	}
	for _, n := range e.Limits {
		if n > 0 {
			return true
		}
	}
	return false
}
