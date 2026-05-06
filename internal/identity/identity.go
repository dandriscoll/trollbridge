// Package identity resolves the client identity for a request. See
// DESIGN.md §8.4. Phase 1 supports source-IP and bearer token; mTLS
// arrives in Phase 2+.
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"

	"github.com/dandriscoll/drawbridge/internal/config"
)

// Resolver converts a client connection + request to a canonical
// identity ID. Returns "anonymous" when no identity matches.
type Resolver struct {
	identities []config.Identity
}

// New constructs a Resolver from configured identities.
func New(identities []config.Identity) *Resolver {
	return &Resolver{identities: identities}
}

// Resolve returns the matching identity ID, or "anonymous".
func (r *Resolver) Resolve(clientAddr string, req *http.Request) string {
	srcIP := stripPort(clientAddr)
	bearer := bearerTokenFromHeader(req)
	bearerHash := ""
	if bearer != "" {
		sum := sha256.Sum256([]byte(bearer))
		bearerHash = hex.EncodeToString(sum[:])
	}

	for _, id := range r.identities {
		if id.Match.BearerTokenSHA256 != "" && id.Match.BearerTokenSHA256 == bearerHash {
			return id.ID
		}
	}
	for _, id := range r.identities {
		if id.Match.SourceIP != "" && id.Match.SourceIP == srcIP {
			return id.ID
		}
	}
	return "anonymous"
}

func stripPort(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func bearerTokenFromHeader(req *http.Request) string {
	v := req.Header.Get("Proxy-Authorization")
	if v == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(v) > len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
		return strings.TrimSpace(v[len(prefix):])
	}
	return ""
}
