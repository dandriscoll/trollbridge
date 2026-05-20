package generalize

import (
	"strings"
	"testing"
)

// TestGeneralizeOne_AxisCoverage pins #170 single-select generalize:
// one concrete entry yields one candidate per applicable axis, in the
// stable order url_segment, hostname_below_tld, ip_block, method.
func TestGeneralizeOne_AxisCoverage(t *testing.T) {
	cases := []struct {
		name  string
		entry string
		want  []struct {
			axis    Axis
			pattern string
		}
	}{
		{
			name:  "method_url_segment_and_host",
			entry: "GET api.example.com/v1/users/123",
			want: []struct {
				axis    Axis
				pattern string
			}{
				{AxisURLSegment, "GET api.example.com/v1/users/*"},
				{AxisHostnameBelowTLD, "GET *.example.com/v1/users/123"},
				{AxisMethod, "* api.example.com/v1/users/123"},
			},
		},
		{
			name:  "ipv4_block_and_method",
			entry: "POST 10.0.0.7/health",
			want: []struct {
				axis    Axis
				pattern string
			}{
				{AxisURLSegment, "POST 10.0.0.7/*"},
				{AxisIPBlock, "POST 10.0.0.0/24/health"},
				{AxisMethod, "* 10.0.0.7/health"},
			},
		},
		{
			name:  "no_axis_applies",
			entry: "* example.com",
			want:  nil,
		},
		{
			name:  "wildcard_entry_skipped",
			entry: "GET api.example.com/v1/*",
			want:  nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GeneralizeOne(tc.entry, "allow")
			if len(got) != len(tc.want) {
				t.Fatalf("candidate count: got %d %+v, want %d", len(got), got, len(tc.want))
			}
			for i, w := range tc.want {
				if got[i].Axis != w.axis || got[i].SuggestedPattern != w.pattern {
					t.Errorf("candidate[%d]: got {%s %q}, want {%s %q}", i, got[i].Axis, got[i].SuggestedPattern, w.axis, w.pattern)
				}
				if len(got[i].SourceEntries) != 1 || got[i].List != "allow" {
					t.Errorf("candidate[%d]: SourceEntries=%v List=%q, want single source on allow", i, got[i].SourceEntries, got[i].List)
				}
			}
		})
	}
}

// TestGeneralizeOne_HostBelowPublicSuffixOnly verifies a bare eTLD+1
// host does not produce a hostname candidate (would over-broaden into
// the public suffix), only the method axis.
func TestGeneralizeOne_HostBelowPublicSuffixOnly(t *testing.T) {
	got := GeneralizeOne("DELETE example.co.uk/x", "deny")
	for _, c := range got {
		if c.Axis == AxisHostnameBelowTLD {
			t.Errorf("eTLD+1 host produced a hostname_below_tld candidate %q (would cross the public suffix)", c.SuggestedPattern)
		}
		if !strings.HasPrefix(c.SuggestedPattern, "DELETE ") && c.Axis != AxisMethod {
			t.Errorf("unexpected candidate %+v", c)
		}
	}
}
