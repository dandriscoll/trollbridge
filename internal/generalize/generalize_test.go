package generalize

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestAxesClosedSetIsThree(t *testing.T) {
	// Closed-set guard. If a fourth axis is added the test fails,
	// forcing the implementer to wire dispatch and update Axes.
	if got := len(Axes); got != 3 {
		t.Fatalf("Axes must enumerate exactly three axes; got %d (%v)", got, Axes)
	}
	want := map[Axis]bool{
		AxisHostnameBelowTLD: true,
		AxisURLSegment:       true,
		AxisMethod:           true,
	}
	for _, a := range Axes {
		if !want[a] {
			t.Errorf("unknown axis in Axes: %q", a)
		}
		delete(want, a)
	}
	for a := range want {
		t.Errorf("Axes missing %q", a)
	}
}

func TestDetectMethod(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		want    []Candidate
	}{
		{
			name: "two distinct methods on same URL",
			entries: []string{
				"GET https://api.example.com/v1/users",
				"POST https://api.example.com/v1/users",
			},
			want: []Candidate{{
				Axis: AxisMethod, List: "allow",
				SourceEntries: []string{
					"GET https://api.example.com/v1/users",
					"POST https://api.example.com/v1/users",
				},
				SuggestedPattern: "* https://api.example.com/v1/users",
			}},
		},
		{
			name:    "single entry produces nothing",
			entries: []string{"GET https://api.example.com/v1/users"},
			want:    nil,
		},
		{
			name: "same method on two URLs is NOT a method-axis candidate",
			entries: []string{
				"GET https://api.example.com/v1/users",
				"GET https://api.example.com/v1/posts",
			},
			want: nil,
		},
		{
			name: "cross-host does not group on method",
			entries: []string{
				"GET https://api.example.com/v1/users",
				"POST https://other.example.com/v1/users",
			},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectMethod(tc.entries, "allow")
			if !equalCandidates(got, tc.want) {
				t.Fatalf("DetectMethod(%v) = %v; want %v", tc.entries, got, tc.want)
			}
		})
	}
}

func TestDetectURLSegment(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		want    []Candidate
	}{
		{
			name: "two URLs differing only in last segment",
			entries: []string{
				"GET https://api.example.com/v1/users/123",
				"GET https://api.example.com/v1/users/456",
			},
			want: []Candidate{{
				Axis: AxisURLSegment, List: "allow",
				SourceEntries: []string{
					"GET https://api.example.com/v1/users/123",
					"GET https://api.example.com/v1/users/456",
				},
				SuggestedPattern: "GET https://api.example.com/v1/users/*",
			}},
		},
		{
			name: "different host: no candidate",
			entries: []string{
				"GET https://api.example.com/v1/users/123",
				"GET https://other.example.com/v1/users/456",
			},
			want: nil,
		},
		{
			name: "different method: no candidate (URL-segment axis only)",
			entries: []string{
				"GET https://api.example.com/v1/users/123",
				"POST https://api.example.com/v1/users/456",
			},
			want: nil,
		},
		{
			name: "two identical entries: no candidate (segments must differ)",
			entries: []string{
				"GET https://api.example.com/v1/users/123",
				"GET https://api.example.com/v1/users/123",
			},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectURLSegment(tc.entries, "allow")
			if !equalCandidates(got, tc.want) {
				t.Fatalf("DetectURLSegment(%v) = %v; want %v", tc.entries, got, tc.want)
			}
		})
	}
}

func TestDetectHostnameBelowTLD(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		wantOk  bool
		wantPat string
	}{
		{
			name: "two subdomains of example.com → *.example.com",
			entries: []string{
				"* https://api.example.com",
				"* https://auth.example.com",
			},
			wantOk:  true,
			wantPat: "* https://*.example.com",
		},
		{
			name: "co.uk public suffix MUST NOT be wildcarded",
			entries: []string{
				"* https://api.co.uk",
				"* https://auth.co.uk",
			},
			wantOk: false,
		},
		{
			name: "different schemes do not group",
			entries: []string{
				"* http://api.example.com",
				"* https://auth.example.com",
			},
			wantOk: false,
		},
		{
			name: "two subdomains under example.co.uk → *.example.co.uk",
			entries: []string{
				"* https://api.example.co.uk",
				"* https://auth.example.co.uk",
			},
			wantOk:  true,
			wantPat: "* https://*.example.co.uk",
		},
		{
			name: "IP literals are skipped (IPs are not generalized; #181 dropped ip_block)",
			entries: []string{
				"* https://10.0.0.1",
				"* https://10.0.0.2",
			},
			wantOk: false,
		},
		{
			name: "single subdomain: no candidate",
			entries: []string{
				"* https://api.example.com",
			},
			wantOk: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectHostnameBelowTLD(tc.entries, "allow")
			if !tc.wantOk {
				if len(got) != 0 {
					t.Fatalf("expected no candidates; got %v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 candidate; got %d (%v)", len(got), got)
			}
			if got[0].SuggestedPattern != tc.wantPat {
				t.Fatalf("got pattern %q; want %q", got[0].SuggestedPattern, tc.wantPat)
			}
		})
	}
}

// TestDetectAll_IPLiteralsNotGeneralized guards the #181 decision: IP-literal
// list entries must not produce any generalization candidate (the ip_block
// axis was dropped because hostlist has no CIDR host shape).
func TestDetectAll_IPLiteralsNotGeneralized(t *testing.T) {
	allow := []string{
		"* https://10.0.0.1",
		"* https://10.0.0.2",
	}
	if got := DetectAll(allow, nil); len(got) != 0 {
		t.Fatalf("IP literals must yield no generalization candidate after #181; got %v", got)
	}
}

func TestAllowAndDenyAreScannedIndependently(t *testing.T) {
	// One pair in allow + one pair in deny should produce TWO
	// candidates (one per list), never a mixed one.
	allow := []string{
		"GET https://api.example.com/v1/users",
		"POST https://api.example.com/v1/users",
	}
	deny := []string{
		"GET https://api.evil.com/v1/users",
		"POST https://api.evil.com/v1/users",
	}
	got := DetectAll(allow, deny)
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates (one per list); got %d (%v)", len(got), got)
	}
	seen := map[string]bool{}
	for _, c := range got {
		seen[c.List] = true
		for _, src := range c.SourceEntries {
			if c.List == "allow" && strings.Contains(src, "evil.com") {
				t.Errorf("allow candidate contained deny entry %q", src)
			}
			if c.List == "deny" && strings.Contains(src, "api.example.com/v1/users") {
				t.Errorf("deny candidate contained allow entry %q", src)
			}
		}
	}
	if !seen["allow"] || !seen["deny"] {
		t.Fatalf("expected both lists; got %v", seen)
	}
}

func TestCanonicalKeyIsStableAcrossInsertOrder(t *testing.T) {
	a := Candidate{SourceEntries: []string{"GET /a", "GET /b", "GET /c"}}
	b := Candidate{SourceEntries: []string{"GET /c", "GET /a", "GET /b"}}
	if a.CanonicalKey() != b.CanonicalKey() {
		t.Fatalf("CanonicalKey unstable: %q vs %q", a.CanonicalKey(), b.CanonicalKey())
	}
}

func TestDeclineFilteringIsDoneByCanonicalKey(t *testing.T) {
	// Two-entry method group; later we ask whether two different
	// orderings of those entries collide on the same key.
	allow := []string{
		"GET https://api.example.com/v1/users",
		"POST https://api.example.com/v1/users",
	}
	got := DetectAll(allow, nil)
	if len(got) == 0 {
		t.Fatalf("expected method candidate; got none")
	}
	// Build a reversed-order "decline" key and confirm it matches
	// the candidate's CanonicalKey.
	reversed := []string{
		"POST https://api.example.com/v1/users",
		"GET https://api.example.com/v1/users",
	}
	sort.Strings(reversed)
	want := strings.Join(reversed, "\x00")
	if got[0].CanonicalKey() != want {
		t.Fatalf("CanonicalKey %q != reversed-sorted-join %q", got[0].CanonicalKey(), want)
	}
}

func equalCandidates(a, b []Candidate) bool {
	if len(a) != len(b) {
		return false
	}
	// Order-insensitive comparison via map by CanonicalKey.
	indexB := map[string]Candidate{}
	for _, c := range b {
		indexB[c.CanonicalKey()+"|"+string(c.Axis)] = c
	}
	for _, c := range a {
		other, ok := indexB[c.CanonicalKey()+"|"+string(c.Axis)]
		if !ok {
			return false
		}
		if c.Axis != other.Axis || c.List != other.List || c.SuggestedPattern != other.SuggestedPattern {
			return false
		}
		if !reflect.DeepEqual(c.SourceEntries, other.SourceEntries) {
			return false
		}
	}
	return true
}
