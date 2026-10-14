package monarch_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devamicus/monarch-go"
	"github.com/devamicus/monarch-go/token"
)

func TestImportAndRestrict(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	_, err := monarch.Open(monarch.Option{Mode: monarch.ModeLive, StateDir: dir, Masters: token.Masters{}, Now: func() time.Time { return now }})
	if err == nil || !strings.Contains(err.Error(), "monarch seal") {
		t.Fatal(err)
	}
	client, err := monarch.Open(monarch.Option{Mode: monarch.ModeLive, StateDir: dir, Masters: token.Masters{"pending": bytes.Repeat([]byte{1}, 32)}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if client.Mode() != monarch.ModeRestricted || client.Allows("sso") {
		t.Fatalf("mode %s allows %v", client.Mode(), client.Allows("sso"))
	}
	masterPub, masterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuePub, issuePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	masters := token.Masters{"master-2026": masterPub}
	client, err = monarch.Open(monarch.Option{Mode: monarch.ModeLive, StateDir: dir, Masters: masters, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, delegation := signSnapshot(t, now, masterPriv, issuePub, issuePriv, client.PublicKey(), token.EnforcementAllow, "")
	if err := client.Import(snapshot, delegation); err != nil {
		t.Fatal(err)
	}
	if !client.Allows("sso") {
		t.Fatal("expected sso")
	}
	if _, _, err := client.Config(); err != nil {
		t.Fatal(err)
	}
	n, ok := client.Limit("nodes")
	if !ok || n != 3 {
		t.Fatalf("limit %d %v", n, ok)
	}
	denied, _ := signSnapshot(t, now.Add(time.Minute), masterPriv, issuePub, issuePriv, client.PublicKey(), token.EnforcementDeny, "revoked")
	later := openOption(dir, masters, now.Add(time.Minute))
	reloaded, err := monarch.Open(later)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Import(denied, delegation); err != nil {
		t.Fatal(err)
	}
	if reloaded.Mode() != monarch.ModeRestricted || reloaded.Reason() != "revoked" {
		t.Fatalf("mode %s reason %s", reloaded.Mode(), reloaded.Reason())
	}
}

func TestGuardAndConfig(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	masterPub, masterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuePub, issuePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	masters := token.Masters{"master-2026": masterPub}
	client, err := monarch.Open(monarch.Option{Mode: monarch.ModeLive, StateDir: dir, Masters: masters, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, cfg, err := client.Config(); !errors.Is(err, monarch.ErrNotServing) || len(cfg) != 0 {
		t.Fatalf("config %v %v", cfg, err)
	}
	started := false
	err = client.Guard(context.Background(), func(context.Context) error {
		started = true
		return nil
	})
	if !errors.Is(err, monarch.ErrNotServing) || started {
		t.Fatalf("started %v err %v", started, err)
	}
	snapshot, delegation := signSnapshot(t, now, masterPriv, issuePub, issuePriv, client.PublicKey(), token.EnforcementAllow, "")
	if err := client.Import(snapshot, delegation); err != nil {
		t.Fatal(err)
	}
	var region any
	err = client.Guard(context.Background(), func(context.Context) error {
		_, cfg, err := client.Config()
		if err != nil {
			return err
		}
		region = cfg["region"]
		return nil
	})
	if err != nil || region != "eu" {
		t.Fatalf("region %v err %v", region, err)
	}
}

func TestHeartbeatAgainstServer(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	masterPub, masterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuePub, issuePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	masters := token.Masters{"master-2026": masterPub}
	client, err := monarch.Open(monarch.Option{Mode: monarch.ModeLive, StateDir: dir, Masters: masters, Now: func() time.Time { return now }, Environment: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, delegation := signSnapshot(t, now, masterPriv, issuePub, issuePriv, client.PublicKey(), token.EnforcementAllow, "")
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"instance_id": "inst_test", "token": snapshot, "delegation": delegation})
	}))
	defer srv.Close()
	var notices []string
	client, err = monarch.Open(monarch.Option{
		Mode: monarch.ModeLive, StateDir: dir, ServerURL: srv.URL, LicenseKey: "mon_live_test", Environment: "prod",
		Masters: masters, Now: func() time.Time { return now },
		Info: func(msg string, _ ...any) { notices = append(notices, msg) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.Mode() != monarch.ModeServing {
		t.Fatal(client.Reason())
	}
	if _, err := os.Stat(filepath.Join(dir, "cache.json")); err != nil {
		t.Fatal(err)
	}
	if len(notices) != 1 || notices[0] != "activated" {
		t.Fatalf("notices %v", notices)
	}
}

func TestOpenImportsLicenseFile(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	masterPub, masterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuePub, issuePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	masters := token.Masters{"master-2026": masterPub}
	first, err := monarch.Open(monarch.Option{Mode: monarch.ModeLive, StateDir: dir, Masters: masters, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, delegation := signSnapshot(t, now, masterPriv, issuePub, issuePriv, first.PublicKey(), token.EnforcementAllow, "")
	path := filepath.Join(dir, "license.json")
	raw, err := json.Marshal(map[string]string{"instance_id": "inst_test", "token": snapshot, "delegation": delegation})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var notices []string
	client, err := monarch.Open(monarch.Option{
		Mode: monarch.ModeLive, StateDir: dir, Masters: masters, LicenseFile: path,
		Now:  func() time.Time { return now },
		Info: func(msg string, _ ...any) { notices = append(notices, msg) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !client.Allows("sso") || client.Mode() != monarch.ModeServing {
		t.Fatalf("mode %s reason %s", client.Mode(), client.Reason())
	}
	if len(notices) != 1 || notices[0] != "imported" {
		t.Fatalf("notices %v", notices)
	}
	started := false
	if err := client.Guard(context.Background(), func(context.Context) error {
		started = true
		return nil
	}); err != nil || !started {
		t.Fatalf("started %v err %v", started, err)
	}

	t.Setenv("MONARCH_LICENSE_FILE", path)
	again, err := monarch.Open(monarch.Option{
		Mode: monarch.ModeLive, StateDir: dir, Masters: masters, Now: func() time.Time { return now },
		Info: func(msg string, _ ...any) { notices = append(notices, msg) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !again.Allows("sso") {
		t.Fatal(again.Reason())
	}
	if notices[len(notices)-1] != "connected" {
		t.Fatalf("notices %v", notices)
	}

	t.Setenv("MONARCH_LICENSE_FILE", filepath.Join(dir, "missing.json"))
	if _, err := monarch.Open(monarch.Option{Mode: monarch.ModeLive, StateDir: dir, Masters: masters, Now: func() time.Time { return now }}); err == nil {
		t.Fatal("expected missing file")
	}
	if _, err := monarch.Open(monarch.Option{Mode: monarch.ModeOff, StateDir: dir, Now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
}

func TestLicenseInstructions(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	masterPub, masterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuePub, issuePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	masters := token.Masters{"master-2026": masterPub}
	var notices []string
	info := func(msg string, _ ...any) { notices = append(notices, msg) }
	first, err := monarch.Open(monarch.Option{
		Mode: monarch.ModeLive, StateDir: dir, Masters: masters, Now: func() time.Time { return now }, Info: info,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "no license configured") {
		t.Fatalf("notices %v", notices)
	}
	pub := base64.RawURLEncoding.EncodeToString(first.PublicKey())
	offline := strings.Index(notices[0], "Offline")
	keyAt := strings.Index(notices[0], "public key: "+pub)
	if offline < 0 || keyAt < offline || strings.Contains(notices[0], "curl") {
		t.Fatalf("notice %s", notices[0])
	}
	for _, part := range []string{"MONARCH_LICENSE_KEY", "MONARCH_LICENSE_FILE"} {
		if !strings.Contains(notices[0], part) {
			t.Fatalf("missing %s in %s", part, notices[0])
		}
	}

	snapshot, delegation := signFile(t, now, masterPriv, issuePub, issuePriv, first.PublicKey())
	if err := first.Import(snapshot, delegation); err != nil {
		t.Fatal(err)
	}
	notices = nil
	expired, err := monarch.Open(monarch.Option{
		Mode: monarch.ModeLive, StateDir: dir, Masters: masters,
		Now: func() time.Time { return now.Add(2 * time.Hour) }, Info: info,
	})
	if err != nil {
		t.Fatal(err)
	}
	if expired.Mode() != monarch.ModeRestricted {
		t.Fatal(expired.Mode())
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "air-gap license expired") || !strings.Contains(notices[0], pub) {
		t.Fatalf("notices %v", notices)
	}

	online := t.TempDir()
	holder, err := monarch.Open(monarch.Option{
		Mode: monarch.ModeLive, StateDir: online, Masters: masters, Now: func() time.Time { return now },
		Info: func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, delegation = signSnapshot(t, now, masterPriv, issuePub, issuePriv, holder.PublicKey(), token.EnforcementAllow, "")
	if err := holder.Import(snapshot, delegation); err != nil {
		t.Fatal(err)
	}
	notices = nil
	if _, err := monarch.Open(monarch.Option{
		Mode: monarch.ModeLive, StateDir: online, Masters: masters,
		Now: func() time.Time { return now.Add(2 * time.Hour) }, Info: info,
	}); err != nil {
		t.Fatal(err)
	}
	if len(notices) != 0 {
		t.Fatalf("heartbeat expiry printed %v", notices)
	}
}

func openOption(dir string, masters token.Masters, now time.Time) monarch.Option {
	return monarch.Option{Mode: monarch.ModeLive, StateDir: dir, Masters: masters, Now: func() time.Time { return now }}
}

func signSnapshot(t *testing.T, now time.Time, masterPriv ed25519.PrivateKey, issuePub ed25519.PublicKey, issuePriv ed25519.PrivateKey, install ed25519.PublicKey, enforcement, reason string) (string, string) {
	t.Helper()
	delegation := token.Delegation{
		Issuer: token.RootIssuer, Subject: "ed-prod", PublicKey: issuePub, Environment: "prod",
		Allow: []string{token.AllowSignToken}, NotBefore: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(90 * 24 * time.Hour).Unix(),
	}
	thumb, err := token.Thumbprint(install)
	if err != nil {
		t.Fatal(err)
	}
	features := map[string]bool{}
	limits := map[string]int64{}
	if enforcement == token.EnforcementAllow {
		features["sso"] = true
		limits["nodes"] = 3
	}
	version := int64(1)
	if enforcement == token.EnforcementDeny {
		version = 2
	}
	claims := token.Claims{
		Schema: token.SchemaV1, Issuer: token.Issuer, Audience: "product", Subject: "inst_test",
		Org: "org_1", License: "lic_1", Version: version, Delivery: token.DeliveryHeartbeat, Enforcement: enforcement, Reason: reason,
		IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		LicenseExpiresAt: now.Add(30 * 24 * time.Hour).Unix(), GraceSeconds: int64((72 * time.Hour).Seconds()),
		Confirmation: token.Confirmation{Thumbprint: thumb},
		Entitlements: token.Entitlements{Features: features, Limits: limits},
		Config:       token.Config{Schema: "appconfig/v1", Values: map[string]any{"region": "eu"}},
		NextCheckin:  600, Environment: "prod", JTI: "jti_1",
	}
	return sign(t, "ed-prod", token.TypToken, issuePriv, mustJSON(t, claims)), sign(t, "master-2026", token.TypDelegation, masterPriv, mustJSON(t, delegation))
}

func signFile(t *testing.T, now time.Time, masterPriv ed25519.PrivateKey, issuePub ed25519.PublicKey, issuePriv ed25519.PrivateKey, install ed25519.PublicKey) (string, string) {
	t.Helper()
	delegation := token.Delegation{
		Issuer: token.RootIssuer, Subject: "ed-prod", PublicKey: issuePub, Environment: "prod",
		Allow: []string{token.AllowSignToken}, NotBefore: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(90 * 24 * time.Hour).Unix(),
	}
	thumb, err := token.Thumbprint(install)
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims{
		Schema: token.SchemaV1, Issuer: token.Issuer, Audience: "product", Subject: "inst_test",
		Org: "org_1", License: "lic_1", Version: 1, Delivery: token.DeliveryFile, Enforcement: token.EnforcementAllow,
		IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		LicenseExpiresAt: now.Add(30 * 24 * time.Hour).Unix(),
		Confirmation:     token.Confirmation{Thumbprint: thumb},
		Entitlements:     token.Entitlements{Features: map[string]bool{"sso": true}, Limits: map[string]int64{"nodes": 3}},
		Config:           token.Config{Schema: "appconfig/v1", Values: map[string]any{"region": "eu"}},
		Environment:      "prod", JTI: "jti_file",
	}
	return sign(t, "ed-prod", token.TypToken, issuePriv, mustJSON(t, claims)), sign(t, "master-2026", token.TypDelegation, masterPriv, mustJSON(t, delegation))
}

func sign(t *testing.T, kid, typ string, key ed25519.PrivateKey, payload []byte) string {
	t.Helper()
	header, err := token.HeaderJSON(typ, kid)
	if err != nil {
		t.Fatal(err)
	}
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
