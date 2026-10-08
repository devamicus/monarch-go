package token_test

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/devamicus/monarch-go/token"
)

func TestVerifyChainsMasterToInstall(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	masterPub, masterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuePub, issuePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	installPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	delegation := token.Delegation{
		Issuer:      token.RootIssuer,
		Subject:     "ed-prod-2026",
		PublicKey:   issuePub,
		Environment: "prod",
		Allow:       []string{token.AllowSignToken},
		NotBefore:   now.Add(-time.Hour).Unix(),
		ExpiresAt:   now.Add(90 * 24 * time.Hour).Unix(),
	}
	delegationCompact := sign(t, "master-2026", token.TypDelegation, masterPriv, mustJSON(t, delegation))
	thumb, err := token.Thumbprint(installPub)
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims{
		Schema: token.SchemaV1, Issuer: token.Issuer, Audience: "product",
		Subject: "inst_1", Org: "org_1", License: "lic_1", Version: 1,
		Delivery: token.DeliveryHeartbeat, Enforcement: token.EnforcementAllow,
		IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		LicenseExpiresAt: now.Add(30 * 24 * time.Hour).Unix(),
		GraceSeconds:     int64((72 * time.Hour).Seconds()),
		Confirmation:     token.Confirmation{Thumbprint: thumb},
		Entitlements:     token.Entitlements{Features: map[string]bool{"sso": true}, Limits: map[string]int64{"nodes": 3}},
		Config:           token.Config{Schema: "appconfig/v1", Values: map[string]any{}},
		NextCheckin:      600, Environment: "prod", JTI: "jti_1",
	}
	tokenCompact := sign(t, delegation.Subject, token.TypToken, issuePriv, mustJSON(t, claims))
	masters := token.Masters{"master-2026": masterPub}

	got, err := token.Verify(tokenCompact, delegationCompact, masters, now, installPub)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Entitlements.Features["sso"] || got.Version != 1 {
		t.Fatalf("claims = %+v", got)
	}

	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := token.Verify(tokenCompact, delegationCompact, masters, now, other); err == nil {
		t.Fatal("expected install mismatch")
	}
}

func TestRejectsAlgorithmSwitch(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	masterPub, masterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	delegation := token.Delegation{
		Issuer: token.RootIssuer, Subject: "ed", PublicKey: masterPub,
		Environment: "prod", Allow: []string{token.AllowSignToken},
		NotBefore: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	compact := sign(t, "master-2026", token.TypDelegation, masterPriv, mustJSON(t, delegation))
	parts := split3(t, compact)
	header, err := token.HeaderJSON(token.TypDelegation, "master-2026")
	if err != nil {
		t.Fatal(err)
	}
	header[len(`{"alg":"`)] = 'n' // corrupt alg tag inside EdDSA; easier to rebuild
	_ = header
	forged := signRaw(t, []byte(`{"alg":"none","kid":"master-2026","typ":"monarch-delegation+jwt"}`), mustJSON(t, delegation), masterPriv)
	_, err = token.VerifyDelegation(forged, token.Masters{"master-2026": masterPub}, now)
	if err == nil {
		t.Fatal("expected algorithm rejection, unused parts", parts)
	}
}

func sign(t *testing.T, kid, typ string, key ed25519.PrivateKey, payload []byte) string {
	t.Helper()
	header, err := token.HeaderJSON(typ, kid)
	if err != nil {
		t.Fatal(err)
	}
	return signRaw(t, header, payload, key)
}

func signRaw(t *testing.T, header, payload []byte, key ed25519.PrivateKey) string {
	t.Helper()
	input := token.SigningInput(header, payload)
	return token.Complete(input, ed25519.Sign(key, []byte(input)))
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func split3(t *testing.T, compact string) [3]string {
	t.Helper()
	var out [3]string
	n := 0
	start := 0
	for i := 0; i <= len(compact); i++ {
		if i == len(compact) || compact[i] == '.' {
			if n > 2 {
				t.Fatal(compact)
			}
			out[n] = compact[start:i]
			n++
			start = i + 1
		}
	}
	return out
}
