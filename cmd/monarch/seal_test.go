package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestFlagAliases(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := run([]string{"seal", "-i"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join("internal", "monarchpin", "unsealed.go")); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"seal", "--init", "--output", "pin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join("pin", "unsealed.go")); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"seal", "-h"}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"seal", "-s", "http://127.0.0.1:1", "-t", "prod"},
		{"seal", "--server", "http://127.0.0.1:1", "--tag", "prod"},
	} {
		err := run(args)
		if err == nil || strings.Contains(err.Error(), "flag provided but not defined") {
			t.Fatal(err)
		}
	}
}

func TestDefaultOutputDir(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := executeSeal(sealOpts{Init: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "internal", "monarchpin", "unsealed.go")); err != nil {
		t.Fatal(err)
	}
}

func TestSealTags(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/master-keys" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{"kid": "master-2026", "public_key": base64.RawURLEncoding.EncodeToString(pub)}},
		})
	}))
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "monarchpin")
	if err := executeSeal(sealOpts{Dir: dir, Init: true}); err != nil {
		t.Fatal(err)
	}
	if err := executeSeal(sealOpts{Server: srv.URL, Tag: "linux", Dir: dir}); err == nil {
		t.Fatal("expected rejected tag")
	}
	if err := executeSeal(sealOpts{Server: srv.URL, Tag: "prod", Dir: dir, HTTP: srv.Client()}); err != nil {
		t.Fatal(err)
	}
	if err := executeSeal(sealOpts{Server: srv.URL, Tag: "staging", Dir: dir, HTTP: srv.Client()}); err != nil {
		t.Fatal(err)
	}
	unsealed, err := os.ReadFile(filepath.Join(dir, "unsealed.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unsealed), "//go:build !prod && !staging") || !strings.Contains(string(unsealed), "return false") || !strings.Contains(string(unsealed), "master-2026") {
		t.Fatalf("unsealed:\n%s", unsealed)
	}
	prod, err := os.ReadFile(filepath.Join(dir, "pin_prod.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(prod), "//go:build prod") || !strings.Contains(string(prod), "return true") {
		t.Fatalf("prod:\n%s", prod)
	}

	root := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(filepath.Join(root, "internal"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(filepath.Join(root, "internal", "monarchpin"), os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	mod := "module example.com/app\n\ngo 1.26.0\n\nrequire github.com/devamicus/monarch-go v0.0.0\n\nreplace github.com/devamicus/monarch-go => " + strconv.Quote(moduleRoot(t)) + "\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	build := func(tags string) error {
		args := []string{"build", "./internal/monarchpin"}
		if tags != "" {
			args = []string{"build", "-tags", tags, "./internal/monarchpin"}
		}
		cmd := exec.Command("go", args...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			return &buildError{err: err, out: out}
		}
		return nil
	}
	if err := build(""); err != nil {
		t.Fatal(err)
	}
	if err := build("prod"); err != nil {
		t.Fatal(err)
	}
	if err := build("staging"); err != nil {
		t.Fatal(err)
	}
	if err := build("prod,staging"); err == nil {
		t.Fatal("expected both tags to fail")
	}
}

type buildError struct {
	err error
	out []byte
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + string(e.out) }

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}
