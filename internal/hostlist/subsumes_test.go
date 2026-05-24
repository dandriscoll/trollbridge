package hostlist

import "testing"

// TestSubsumes pins #177: a generalized pattern must be recognized as
// covering the narrower entries it replaces, across each axis a
// generalization can widen (method, scheme, port, path, host).
func TestSubsumes(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		entry   string
		want    bool
	}{
		// path-segment wildcard (the common case)
		{"path wildcard covers concrete", "GET api.example.com/v1/users/*", "GET api.example.com/v1/users/123", true},
		{"path wildcard covers other concrete", "GET api.example.com/v1/users/*", "GET api.example.com/v1/users/456", true},
		{"path wildcard does not cover different prefix", "GET api.example.com/v1/users/*", "GET api.example.com/v1/orders/1", false},
		// method widening
		{"any-method covers GET", "* api.example.com/x", "GET api.example.com/x", true},
		{"GET does not cover any-method", "GET api.example.com/x", "api.example.com/x", false},
		{"GET does not cover POST", "GET api.example.com/x", "POST api.example.com/x", false},
		// port drop (pattern omits port → anyPort; scheme omitted → anyScheme)
		{"no-port covers :443", "GET api.example.com/v1/users/*", "GET https://api.example.com:443/v1/users/9", true},
		{"specific port not covered by other port", "GET api.example.com:8080/x", "GET api.example.com:9090/x", false},
		// host wildcard below the suffix
		{"*.example.com covers subdomain", "GET *.example.com/x", "GET api.example.com/x", true},
		{"*.example.com does not cover apex", "GET *.example.com/x", "GET example.com/x", false},
		{"*.example.com does not cover other domain", "GET *.example.com/x", "GET api.other.com/x", false},
		{"*.example.com covers deeper subdomain wildcard", "*.example.com", "*.api.example.com", true},
		// broader entry must NOT be removed
		{"exact does not subsume wildcard entry", "GET api.example.com/v1/users/123", "GET api.example.com/v1/users/*", false},
		{"prefix does not subsume any-path entry", "GET api.example.com/v1/*", "GET api.example.com/v1", false},
		// identity
		{"pattern subsumes itself", "GET api.example.com/v1/users/*", "GET api.example.com/v1/users/*", true},
		// unrelated
		{"unrelated host", "GET api.example.com/*", "GET totally.different.net/x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Subsumes(tc.pattern, tc.entry); got != tc.want {
				t.Errorf("Subsumes(%q, %q) = %v, want %v", tc.pattern, tc.entry, got, tc.want)
			}
		})
	}
}
