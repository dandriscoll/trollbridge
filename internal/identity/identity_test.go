package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/dandriscoll/drawbridge/internal/config"
)

func TestResolver_AnonymousByDefault(t *testing.T) {
	r := New(nil)
	got := r.Resolve("127.0.0.1:9000", &http.Request{Header: http.Header{}})
	if got != "anonymous" {
		t.Errorf("got %q, want anonymous", got)
	}
}

func TestResolver_SourceIPMatch(t *testing.T) {
	r := New([]config.Identity{
		{ID: "dev", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}},
	})
	got := r.Resolve("127.0.0.1:54321", &http.Request{Header: http.Header{}})
	if got != "dev" {
		t.Errorf("got %q, want dev", got)
	}
}

func TestResolver_BearerTokenMatch(t *testing.T) {
	tok := "supersecret"
	sum := sha256.Sum256([]byte(tok))
	hash := hex.EncodeToString(sum[:])

	r := New([]config.Identity{
		{ID: "ci", Match: config.IdentityMatch{BearerTokenSHA256: hash}},
	})
	req := &http.Request{Header: http.Header{}}
	req.Header.Set("Proxy-Authorization", "Bearer "+tok)
	got := r.Resolve("10.0.0.1:1234", req)
	if got != "ci" {
		t.Errorf("got %q, want ci", got)
	}
}

func TestResolver_BearerBeatsSourceIP(t *testing.T) {
	tok := "tk"
	sum := sha256.Sum256([]byte(tok))
	hash := hex.EncodeToString(sum[:])

	r := New([]config.Identity{
		{ID: "by-ip", Match: config.IdentityMatch{SourceIP: "10.0.0.1"}},
		{ID: "by-token", Match: config.IdentityMatch{BearerTokenSHA256: hash}},
	})
	req := &http.Request{Header: http.Header{}}
	req.Header.Set("Proxy-Authorization", "Bearer "+tok)
	got := r.Resolve("10.0.0.1:1234", req)
	if got != "by-token" {
		t.Errorf("got %q, want by-token (bearer beats source IP)", got)
	}
}
