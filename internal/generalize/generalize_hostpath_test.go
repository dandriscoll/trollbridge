package generalize

import "testing"

// TestDetectHostPath pins #186: a host whose path entries span ≥2
// distinct prefixes yields a single host-wide `host/*` candidate
// covering ALL of them, while a host whose paths share one prefix
// yields nothing here (DetectURLSegment already covers that case).
func TestDetectHostPath(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		wantOk  bool
		wantPat string
		wantSrc int
	}{
		{
			name: "two prefixes, singleton buckets — only host-path covers all",
			entries: []string{
				"GET https://api.example.com/v1/users/1",
				"GET https://api.example.com/v1/orders/2",
			},
			wantOk:  true,
			wantPat: "GET https://api.example.com/*",
			wantSrc: 2,
		},
		{
			name: "three entries spanning two prefixes — host-path covers all three",
			entries: []string{
				"GET https://api.example.com/v1/users/1",
				"GET https://api.example.com/v1/users/2",
				"GET https://api.example.com/v1/orders/3",
			},
			wantOk:  true,
			wantPat: "GET https://api.example.com/*",
			wantSrc: 3,
		},
		{
			name: "single shared prefix — DetectURLSegment owns it, host-path quiet",
			entries: []string{
				"GET https://api.example.com/v1/users/1",
				"GET https://api.example.com/v1/users/2",
			},
			wantOk: false,
		},
		{
			name: "single path entry — nothing to generalize",
			entries: []string{
				"GET https://api.example.com/v1/users/1",
			},
			wantOk: false,
		},
		{
			name: "different methods do not group",
			entries: []string{
				"GET https://api.example.com/v1/users/1",
				"POST https://api.example.com/v1/orders/2",
			},
			wantOk: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectHostPath(tc.entries, "allow")
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
				t.Errorf("pattern = %q; want %q", got[0].SuggestedPattern, tc.wantPat)
			}
			if got[0].Axis != AxisURLSegment {
				t.Errorf("axis = %q; want url_segment (host-wide path is the url_segment class)", got[0].Axis)
			}
			if len(got[0].SourceEntries) != tc.wantSrc {
				t.Errorf("source count = %d; want %d (must cover the whole host)", len(got[0].SourceEntries), tc.wantSrc)
			}
		})
	}
}

// TestDetectAll_HostPathAndSubsetCoexist pins that the deep-prefix
// subset and the host-wide candidate are BOTH produced for a host with
// a coverable subset plus a stray prefix — the subset remains available
// while the host-wide one (broader coverage) is also offered.
func TestDetectAll_HostPathAndSubsetCoexist(t *testing.T) {
	allow := []string{
		"GET https://api.example.com/v1/users/1",
		"GET https://api.example.com/v1/users/2",
		"GET https://api.example.com/v1/orders/3",
	}
	got := DetectAll(allow, nil)
	var subset, hostwide bool
	for _, c := range got {
		switch c.SuggestedPattern {
		case "GET https://api.example.com/v1/users/*":
			subset = len(c.SourceEntries) == 2
		case "GET https://api.example.com/*":
			hostwide = len(c.SourceEntries) == 3
		}
	}
	if !subset {
		t.Errorf("expected the /v1/users/* subset candidate (2 sources); got %v", got)
	}
	if !hostwide {
		t.Errorf("expected the host-wide /* candidate (3 sources); got %v", got)
	}
}
