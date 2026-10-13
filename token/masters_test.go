package token_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/devamicus/monarch-go/token"
)

func TestParseMasters(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	line := "master-2026:" + base64.RawURLEncoding.EncodeToString(pub)
	got, err := token.ParseMasters(line + ", " + line)
	if err == nil || got != nil {
		t.Fatalf("duplicate: %v %v", got, err)
	}
	got, err = token.ParseMasters("master-2026:" + line)
	if err == nil {
		t.Fatal("expected bad key")
	}
	got, err = token.ParseMasters(line)
	if err != nil {
		t.Fatal(err)
	}
	if !got["master-2026"].Equal(pub) {
		t.Fatal("public key mismatch")
	}
}
