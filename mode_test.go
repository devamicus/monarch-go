package monarch_test

import (
	"context"
	"crypto/ed25519"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devamicus/monarch-go"
	"github.com/devamicus/monarch-go/token"
)

func TestDevelopmentModes(t *testing.T) {
	t.Setenv("MONARCH_MODE", "")
	dir := filepath.Join(t.TempDir(), "state")
	var notes []string
	client, err := monarch.Open(monarch.Option{
		StateDir: dir,
		Info:     func(msg string, _ ...any) { notes = append(notes, msg) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if client.Mode() != monarch.ModeServing || !client.Allows("sso") {
		t.Fatalf("mode %s", client.Mode())
	}
	rev, cfg, err := client.Config()
	if err != nil || rev != 0 || len(cfg) != 0 {
		t.Fatalf("config %d %v %v", rev, cfg, err)
	}
	n, ok := client.Limit("warehouses")
	if !ok || n != math.MaxInt64 {
		t.Fatalf("limit %d %v", n, ok)
	}
	started := false
	if err := client.Guard(context.Background(), func(context.Context) error {
		started = true
		return nil
	}); err != nil || !started {
		t.Fatalf("started %v err %v", started, err)
	}
	if len(notes) != 1 || notes[0] != "license check disabled for development" {
		t.Fatalf("notes %v", notes)
	}
	if err := client.Activate(context.Background()); err == nil {
		t.Fatal("activate while disabled")
	}

	path := filepath.Join(t.TempDir(), "monarch.local.json")
	if err := os.WriteFile(path, []byte(`{"features":{"sso":true},"limits":{"warehouses":3},"config":{"revision":4,"values":{"region":"local"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	notes = nil
	client, err = monarch.Open(monarch.Option{Mode: monarch.ModeFile, File: path, Info: func(msg string, _ ...any) { notes = append(notes, msg) }})
	if err != nil {
		t.Fatal(err)
	}
	if client.Allows("billing") || !client.Allows("sso") {
		t.Fatal(client.Allows("sso"))
	}
	n, ok = client.Limit("warehouses")
	if !ok || n != 3 {
		t.Fatalf("limit %d %v", n, ok)
	}
	rev, cfg, err = client.Config()
	if err != nil || rev != 4 || cfg["region"] != "local" {
		t.Fatalf("config %d %v %v", rev, cfg, err)
	}
	if len(notes) != 1 || notes[0] != "using "+path+" for development" {
		t.Fatalf("notes %v", notes)
	}
	if _, err := monarch.Open(monarch.Option{Mode: monarch.ModeFile, File: filepath.Join(t.TempDir(), "missing.json")}); err == nil {
		t.Fatal("missing file")
	}
}

func TestSealedRejectsDevelopment(t *testing.T) {
	t.Setenv("MONARCH_MODE", "off")
	_, err := monarch.Open(monarch.Option{Sealed: true, Masters: token.Masters{"master-2026": make(ed25519.PublicKey, 32)}})
	if err == nil {
		t.Fatal("expected rejection")
	}
	t.Setenv("MONARCH_MODE", "")
	dir := t.TempDir()
	client, err := monarch.Open(monarch.Option{Sealed: true, StateDir: dir, Masters: token.Masters{"master-2026": make(ed25519.PublicKey, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if client.Mode() != monarch.ModeRestricted {
		t.Fatal(client.Mode())
	}
}

func TestConnectedNotice(t *testing.T) {
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
	client, err := monarch.Open(openOption(dir, masters, now))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, delegation := signSnapshot(t, now, masterPriv, issuePub, issuePriv, client.PublicKey(), token.EnforcementAllow, "")
	if err := client.Import(snapshot, delegation); err != nil {
		t.Fatal(err)
	}
	var notes []string
	opt := openOption(dir, masters, now)
	opt.ServerURL = "https://monarch.example.com"
	opt.Info = func(msg string, args ...any) { notes = append(notes, msg+" "+arg(args, "instance")) }
	if _, err := monarch.Open(opt); err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 || notes[0] != "connected inst_test" {
		t.Fatalf("notes %v", notes)
	}
}

func arg(args []any, key string) string {
	for i := 0; i+1 < len(args); i += 2 {
		if args[i] == key {
			s, _ := args[i+1].(string)
			return s
		}
	}
	return ""
}
