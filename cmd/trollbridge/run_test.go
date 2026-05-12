package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// TestDerivePersistPattern pins #49's "full URL for now" choice. The
// table covers each request shape the daemon sees.
func TestDerivePersistPattern(t *testing.T) {
	cases := []struct {
		name string
		req  *types.RequestEvent
		want string
	}{
		{
			name: "CONNECT https tunneled",
			req:  &types.RequestEvent{Method: "CONNECT", Scheme: "https-tunneled", Host: "api.github.com", Port: 443},
			want: "CONNECT api.github.com:443",
		},
		{
			name: "CONNECT no port",
			req:  &types.RequestEvent{Method: "CONNECT", Scheme: "https-tunneled", Host: "api.github.com"},
			want: "CONNECT api.github.com",
		},
		{
			name: "intercepted https with path",
			req:  &types.RequestEvent{Method: "GET", Scheme: "https-intercepted", Host: "api.github.com", Port: 443, Path: "/v1/foo"},
			want: "GET https://api.github.com:443/v1/foo",
		},
		{
			name: "plain http with path",
			req:  &types.RequestEvent{Method: "POST", Scheme: "http", Host: "api.example.com", Port: 80, Path: "/v2/bar"},
			want: "POST http://api.example.com:80/v2/bar",
		},
		{
			name: "missing scheme defaults to http",
			req:  &types.RequestEvent{Method: "GET", Host: "api.example.com", Port: 8080, Path: "/baz"},
			want: "GET http://api.example.com:8080/baz",
		},
		{
			name: "nil request",
			req:  nil,
			want: "",
		},
		{
			name: "empty host",
			req:  &types.RequestEvent{Method: "GET", Scheme: "https", Port: 443, Path: "/"},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := derivePersistPattern(tc.req)
			if got != tc.want {
				t.Errorf("derivePersistPattern(%+v) = %q, want %q", tc.req, got, tc.want)
			}
		})
	}
}

// TestPrintRunStartupBanner_NamesAddrModeAndCommands closes issue #15:
// when `trollbridge run` starts on a TTY, the operator sees a one-
// screen "you're up — try this next" banner with the listen address,
// the policy mode, and copy-pasteable next-step commands.
func TestPrintRunStartupBanner_NamesAddrModeAndCommands(t *testing.T) {
	var buf bytes.Buffer
	printRunStartupBanner(&buf, "127.0.0.1:8080", "default-deny")
	out := buf.String()
	for _, want := range []string{
		"trollbridge is listening on 127.0.0.1:8080",
		"mode: default-deny",
		"trollbridge test https://example.com",
		"trollbridge env",
		"Ctrl-C",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("banner missing %q in:\n%s", want, out)
		}
	}
}

func TestPrintRunStartupBanner_ReflectsBindAddress(t *testing.T) {
	var buf bytes.Buffer
	printRunStartupBanner(&buf, "0.0.0.0:9090", "default-allow")
	out := buf.String()
	if !strings.Contains(out, "0.0.0.0:9090") {
		t.Errorf("banner did not reflect bind address; got:\n%s", out)
	}
	if !strings.Contains(out, "default-allow") {
		t.Errorf("banner did not reflect mode; got:\n%s", out)
	}
	// default-allow should NOT trigger the deny-by-default note.
	if strings.Contains(out, "first request will be declined") {
		t.Errorf("non-deny mode should not print the deny note; got:\n%s", out)
	}
}

// TestPrintRunStartupBanner_DefaultDenyNamesFirstRequestBehavior
// closes issue #16: under default-deny, the operator's first
// request will be declined (HTTP 470). The startup banner should
// name this so the operator interprets the decline as policy
// rather than a setup error.
func TestPrintRunStartupBanner_DefaultDenyNamesFirstRequestBehavior(t *testing.T) {
	var buf bytes.Buffer
	printRunStartupBanner(&buf, "127.0.0.1:8080", "default-deny")
	out := buf.String()
	for _, want := range []string{
		"first request will be declined",
		"HTTP 470",
		"allow <hostname>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("default-deny banner missing %q in:\n%s", want, out)
		}
	}
}
