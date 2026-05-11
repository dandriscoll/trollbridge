package server

import (
	"testing"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// TestOpURLForRequest_SuppressesDefaultPortsAndCollapsesScheme pins
// #64: the operator-facing URL string suppresses :443 for HTTPS
// (including the internal "https-tunneled" / "https-intercepted"
// scheme tokens) and :80 for HTTP. CONNECT defaults to 443 too.
// Non-default ports stay explicit.
func TestOpURLForRequest_SuppressesDefaultPortsAndCollapsesScheme(t *testing.T) {
	cases := []struct {
		name string
		req  *types.RequestEvent
		want string
	}{
		{
			name: "https default port omitted",
			req:  &types.RequestEvent{Method: "GET", Scheme: "https", Host: "api.example.com", Port: 443, Path: "/v1"},
			want: "https://api.example.com/v1",
		},
		{
			name: "https-tunneled collapses to https and omits :443",
			req:  &types.RequestEvent{Method: "GET", Scheme: "https-tunneled", Host: "api.example.com", Port: 443, Path: "/v1"},
			want: "https://api.example.com/v1",
		},
		{
			name: "https-intercepted collapses to https and omits :443",
			req:  &types.RequestEvent{Method: "GET", Scheme: "https-intercepted", Host: "api.example.com", Port: 443, Path: "/v1"},
			want: "https://api.example.com/v1",
		},
		{
			name: "https non-default port stays",
			req:  &types.RequestEvent{Method: "GET", Scheme: "https", Host: "api.example.com", Port: 8443, Path: "/v1"},
			want: "https://api.example.com:8443/v1",
		},
		{
			name: "http default port omitted",
			req:  &types.RequestEvent{Method: "GET", Scheme: "http", Host: "api.example.com", Port: 80, Path: "/v1"},
			want: "http://api.example.com/v1",
		},
		{
			name: "http non-default port stays",
			req:  &types.RequestEvent{Method: "GET", Scheme: "http", Host: "api.example.com", Port: 8080, Path: "/v1"},
			want: "http://api.example.com:8080/v1",
		},
		{
			name: "CONNECT default 443 omits port",
			req:  &types.RequestEvent{Method: "CONNECT", Scheme: "", Host: "api.example.com", Port: 443},
			want: "api.example.com",
		},
		{
			name: "CONNECT non-default port stays",
			req:  &types.RequestEvent{Method: "CONNECT", Scheme: "", Host: "api.example.com", Port: 8443},
			want: "api.example.com:8443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := opURLForRequest(tc.req); got != tc.want {
				t.Errorf("opURLForRequest = %q, want %q", got, tc.want)
			}
		})
	}
}
