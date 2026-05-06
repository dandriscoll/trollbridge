package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/dandriscoll/drawbridge/internal/approvals"
	"github.com/dandriscoll/drawbridge/internal/policy"
	"github.com/dandriscoll/drawbridge/internal/sessions"
)

func bootControl(t *testing.T, mode, bearerSHA string) (*Server, string, context.CancelFunc) {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	q := approvals.New(8, time.Second, "deny")
	tk := sessions.New()
	eng, _ := policy.NewEngine("default-deny", nil, policy.KnownModifiers())
	s := New(addr, q, tk, eng)
	s.SetAuth(mode, bearerSHA)
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := s.ListenAndServe(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	return s, addr, cancel
}

func TestControl_AuthNoneAllows(t *testing.T) {
	_, addr, cancel := bootControl(t, "none", "")
	defer cancel()
	resp, err := http.Get("http://" + addr + "/v1/holds")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

func TestControl_BearerRefusesMissingToken(t *testing.T) {
	tok := "supersecret"
	sum := sha256.Sum256([]byte(tok))
	hash := hex.EncodeToString(sum[:])
	_, addr, cancel := bootControl(t, "bearer", hash)
	defer cancel()

	resp, err := http.Get("http://" + addr + "/v1/holds")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got == "" {
		t.Error("missing WWW-Authenticate header on 401")
	}
}

func TestControl_BearerAcceptsCorrectToken(t *testing.T) {
	tok := "secret-token"
	sum := sha256.Sum256([]byte(tok))
	hash := hex.EncodeToString(sum[:])
	_, addr, cancel := bootControl(t, "bearer", hash)
	defer cancel()

	req, _ := http.NewRequest("GET", "http://"+addr+"/v1/holds", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status: got %d, want 200; body=%s", resp.StatusCode, string(body))
	}
}

func TestControl_HealthzAlwaysReachable(t *testing.T) {
	tok := "secret-token"
	sum := sha256.Sum256([]byte(tok))
	hash := hex.EncodeToString(sum[:])
	_, addr, cancel := bootControl(t, "bearer", hash)
	defer cancel()

	resp, err := http.Get("http://" + addr + "/v1/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}
