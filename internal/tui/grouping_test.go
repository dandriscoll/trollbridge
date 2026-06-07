package tui

import (
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestDisplayedOps_GroupsIdenticalMethodURL pins #63: three ops with
// the same (Method, URL) collapse to one row with Count=3; the
// representative is the newest by UpdatedAt.
func TestDisplayedOps_GroupsIdenticalMethodURL(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			{RequestID: "c", Method: "GET", URL: "https://api.example.com/x", Status: "200", UpdatedAt: t0.Add(2 * time.Second)},
			{RequestID: "b", Method: "GET", URL: "https://api.example.com/x", Status: "200", UpdatedAt: t0.Add(1 * time.Second)},
			{RequestID: "a", Method: "GET", URL: "https://api.example.com/x", Status: "200", UpdatedAt: t0},
		},
	}
	got := DisplayedOps(m)
	if len(got) != 1 {
		t.Fatalf("groups len = %d, want 1", len(got))
	}
	if got[0].Count != 3 {
		t.Errorf("Count = %d, want 3", got[0].Count)
	}
	if got[0].RequestID != "c" {
		t.Errorf("representative RequestID = %q, want %q (newest)", got[0].RequestID, "c")
	}
}

// TestDisplayedOps_DistinctURLsStayDistinct — two URLs → two rows.
func TestDisplayedOps_DistinctURLsStayDistinct(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			{RequestID: "x1", Method: "GET", URL: "https://a/", Status: "200", UpdatedAt: t0.Add(2 * time.Second)},
			{RequestID: "y1", Method: "GET", URL: "https://b/", Status: "200", UpdatedAt: t0.Add(1 * time.Second)},
		},
	}
	got := DisplayedOps(m)
	if len(got) != 2 {
		t.Fatalf("groups len = %d, want 2", len(got))
	}
	for _, o := range got {
		if o.Count != 1 {
			t.Errorf("Count = %d for %q, want 1", o.Count, o.URL)
		}
	}
}

// TestBrailleCounter_LogScaleAndCap pins the logarithmic scale and
// 8-dot cap.
func TestBrailleCounter_LogScaleAndCap(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, " "},
		{1, " "},
		{2, "⠁"},
		{3, "⠁"},
		{4, "⠃"},
		{7, "⠃"},
		{8, "⠇"},
		{15, "⠇"},
		{16, "⠏"},
		{32, "⠟"},
		{64, "⠿"},
		{128, "⡿"},
		{256, "⣿"},
		{4096, "⣿"},
	}
	for _, tc := range cases {
		if got := brailleCounter(tc.n); got != tc.want {
			t.Errorf("brailleCounter(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

// --------- #119: similar-URL folding (generalizes #63) ---------

// TestDisplayedOps_FoldsSameHostDirectory pins #119: resolved ops to
// the same host + path directory + method + status collapse to one
// row; the representative is the newest by UpdatedAt.
func TestDisplayedOps_FoldsSameHostDirectory(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			{RequestID: "a", Method: "GET", URL: "https://files.example.com/build/out/a.o", Status: "200", UpdatedAt: t0},
			{RequestID: "c", Method: "GET", URL: "https://files.example.com/build/out/c.o", Status: "200", UpdatedAt: t0.Add(2 * time.Second)},
			{RequestID: "b", Method: "GET", URL: "https://files.example.com/build/out/b.o", Status: "200", UpdatedAt: t0.Add(1 * time.Second)},
		},
	}
	got := DisplayedOps(m)
	if len(got) != 1 {
		t.Fatalf("groups len = %d, want 1 (same host+dir+method+status)", len(got))
	}
	if got[0].Count != 3 {
		t.Errorf("Count = %d, want 3", got[0].Count)
	}
	if got[0].RequestID != "c" {
		t.Errorf("representative RequestID = %q, want %q (newest)", got[0].RequestID, "c")
	}
	if got[0].URL != "https://files.example.com/build/out/c.o" {
		t.Errorf("representative URL = %q, want the newest member's URL", got[0].URL)
	}
}

// TestDisplayedOps_DifferentDirectoryStaysSeparate — same host, two
// different path directories → two rows.
func TestDisplayedOps_DifferentDirectoryStaysSeparate(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			{RequestID: "1", Method: "GET", URL: "https://api.github.com/repos/x/issues/42", Status: "200", UpdatedAt: t0.Add(2 * time.Second)},
			{RequestID: "2", Method: "GET", URL: "https://api.github.com/users/y/gists/3", Status: "200", UpdatedAt: t0.Add(1 * time.Second)},
		},
	}
	if got := DisplayedOps(m); len(got) != 2 {
		t.Fatalf("groups len = %d, want 2 (different directories)", len(got))
	}
}

// TestDisplayedOps_DifferentHostStaysSeparate — identical path
// directory on two different hosts → two rows.
func TestDisplayedOps_DifferentHostStaysSeparate(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			{RequestID: "1", Method: "GET", URL: "https://a.example.com/v1/x", Status: "200", UpdatedAt: t0.Add(time.Second)},
			{RequestID: "2", Method: "GET", URL: "https://b.example.com/v1/y", Status: "200", UpdatedAt: t0},
		},
	}
	if got := DisplayedOps(m); len(got) != 2 {
		t.Fatalf("groups len = %d, want 2 (different hosts)", len(got))
	}
}

// TestDisplayedOps_DifferentStatusStaysSeparate pins the #119
// outcome-gating decision: the SAME URL with two different statuses
// does NOT fold (a denied request can never hide inside a fold of
// 200s). This is a deliberate behavior change from #63, which folded
// purely on (Method, URL) and ignored status.
func TestDisplayedOps_DifferentStatusStaysSeparate(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			{RequestID: "1", Method: "GET", URL: "https://h.example/api/thing", Status: "200", UpdatedAt: t0.Add(time.Second)},
			{RequestID: "2", Method: "GET", URL: "https://h.example/api/thing", Status: opstream.StatusDenied, UpdatedAt: t0},
		},
	}
	if got := DisplayedOps(m); len(got) != 2 {
		t.Fatalf("groups len = %d, want 2 (200 must not fold with denied)", len(got))
	}
}

// TestDisplayedOps_DifferentMethodStaysSeparate — same host+dir+status,
// different method → two rows.
func TestDisplayedOps_DifferentMethodStaysSeparate(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			{RequestID: "1", Method: "GET", URL: "https://h.example/api/thing", Status: "200", UpdatedAt: t0.Add(time.Second)},
			{RequestID: "2", Method: "POST", URL: "https://h.example/api/thing", Status: "200", UpdatedAt: t0},
		},
	}
	if got := DisplayedOps(m); len(got) != 2 {
		t.Fatalf("groups len = %d, want 2 (different methods)", len(got))
	}
}

// TestDisplayedOps_PendingNeverFolds pins the #119 pending exemption:
// not-yet-resolved ops (pending / signaled / checking) each stay an
// individual row, even when they would otherwise share a similarity
// key — so the a/d keys always target one unambiguous request.
func TestDisplayedOps_PendingNeverFolds(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			// Two identical pending requests — must NOT fold.
			{RequestID: "p1", Method: "GET", URL: "https://h.example/d/x", Status: opstream.StatusPending, HoldID: "hold-1", UpdatedAt: t0.Add(time.Second)},
			{RequestID: "p2", Method: "GET", URL: "https://h.example/d/x", Status: opstream.StatusPending, HoldID: "hold-2", UpdatedAt: t0},
			// A resolved sibling in the same host+dir — must NOT absorb the pendings.
			{RequestID: "r1", Method: "GET", URL: "https://h.example/d/y", Status: "200", UpdatedAt: t0.Add(2 * time.Second)},
			{RequestID: "s1", Method: "GET", URL: "https://h.example/d/z", Status: opstream.StatusSignaled, HoldID: "hold-3", UpdatedAt: t0.Add(3 * time.Second)},
			{RequestID: "c1", Method: "GET", URL: "https://h.example/d/w", Status: opstream.StatusChecking, UpdatedAt: t0.Add(4 * time.Second)},
		},
	}
	got := DisplayedOps(m)
	if len(got) != 5 {
		t.Fatalf("groups len = %d, want 5 (2 pending + 1 resolved + 1 signaled + 1 checking, none folded)", len(got))
	}
	for _, o := range got {
		if o.Count != 1 {
			t.Errorf("row %s Count = %d, want 1", o.RequestID, o.Count)
		}
	}
}

// TestDisplayedOps_PendingFoldsBySharedHold pins the display half of
// #206: when retries of the same URL coalesce onto ONE hold (queue-side
// coalescing), their pending ops fold into a single actionable row
// carrying the count — so the operator no longer sees the same URL
// listed ~20 times. The representative is the newest by UpdatedAt and
// the row's HoldID is the shared hold (so approve/deny resolves all).
func TestDisplayedOps_PendingFoldsBySharedHold(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	ops := []opstream.Op{}
	for i := 0; i < 20; i++ {
		ops = append(ops, opstream.Op{
			RequestID: "p" + itoaPort(i), Method: "GET",
			URL:    "https://example.com/foo",
			Status: opstream.StatusPending, HoldID: "hold-shared",
			UpdatedAt: t0.Add(time.Duration(i) * time.Second),
		})
	}
	got := DisplayedOps(Model{Ops: ops})
	if len(got) != 1 {
		t.Fatalf("groups len = %d, want 1 (20 retries on one hold fold)", len(got))
	}
	if got[0].Count != 20 {
		t.Errorf("Count = %d, want 20", got[0].Count)
	}
	if got[0].HoldID != "hold-shared" {
		t.Errorf("HoldID = %q, want hold-shared (approve must target the shared hold)", got[0].HoldID)
	}
	if got[0].RequestID != "p"+itoaPort(19) {
		t.Errorf("representative RequestID = %q, want newest (p19)", got[0].RequestID)
	}
}

// TestDisplayedOps_PendingDistinctHoldsStaySeparate guards the other
// side: pending ops on DIFFERENT holds (e.g. different identities) must
// stay separate rows — folding is by shared hold, not by URL.
func TestDisplayedOps_PendingDistinctHoldsStaySeparate(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	got := DisplayedOps(Model{Ops: []opstream.Op{
		{RequestID: "p1", Method: "GET", URL: "https://example.com/foo", Status: opstream.StatusPending, HoldID: "hold-1", UpdatedAt: t0},
		{RequestID: "p2", Method: "GET", URL: "https://example.com/foo", Status: opstream.StatusPending, HoldID: "hold-2", UpdatedAt: t0.Add(time.Second)},
	}})
	if len(got) != 2 {
		t.Fatalf("groups len = %d, want 2 (distinct holds do not fold)", len(got))
	}
}

// TestDisplayedOps_FilesAtRootFold — files directly under the host
// root share directory "/" and fold.
func TestDisplayedOps_FilesAtRootFold(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			{RequestID: "1", Method: "GET", URL: "https://cdn.example/a.js", Status: "200", UpdatedAt: t0},
			{RequestID: "2", Method: "GET", URL: "https://cdn.example/b.js", Status: "200", UpdatedAt: t0.Add(time.Second)},
		},
	}
	got := DisplayedOps(m)
	if len(got) != 1 || got[0].Count != 2 {
		t.Fatalf("got %d rows (Count of first = %d), want 1 row Count 2 (both at dir /)", len(got), countOf(got))
	}
}

// TestDisplayedOps_MalformedURLFoldsOnlyWithIdentical — a URL that
// does not parse degrades safely: it folds only with a byte-identical
// string, never with a dissimilar one.
func TestDisplayedOps_MalformedURLFoldsOnlyWithIdentical(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			{RequestID: "1", Method: "GET", URL: "://not a url", Status: "200", UpdatedAt: t0},
			{RequestID: "2", Method: "GET", URL: "://not a url", Status: "200", UpdatedAt: t0.Add(time.Second)},
			{RequestID: "3", Method: "GET", URL: "://different bad", Status: "200", UpdatedAt: t0.Add(2 * time.Second)},
		},
	}
	got := DisplayedOps(m)
	if len(got) != 2 {
		t.Fatalf("groups len = %d, want 2 (identical-malformed fold, distinct-malformed separate)", len(got))
	}
}

// TestOpGroupHostDir pins the (host, directory) extraction.
func TestOpGroupHostDir(t *testing.T) {
	cases := []struct {
		url, host, dir string
	}{
		{"https://api.github.com/repos/x/issues/42", "api.github.com", "/repos/x/issues/"},
		{"https://api.github.com/repos/x/", "api.github.com", "/repos/x/"},
		{"https://cdn.example/file.txt", "cdn.example", "/"},
		{"https://cdn.example/", "cdn.example", "/"},
		{"https://cdn.example", "cdn.example", "/"},
		{"https://h.example:8443/a/b", "h.example:8443", "/a/"},
		{"https-intercepted://h.example/p/q", "h.example", "/p/"},
		// CONNECT / TLS ops are recorded scheme-less (bare host or
		// host:port, no path) — url.Parse yields no host, so the whole
		// string is the host and the directory is empty.
		{"api.github.com", "api.github.com", ""},
		{"files.example.com:8443", "files.example.com:8443", ""},
		{"://not a url", "://not a url", ""},
	}
	for _, tc := range cases {
		host, dir := opGroupHostDir(tc.url)
		if host != tc.host || dir != tc.dir {
			t.Errorf("opGroupHostDir(%q) = (%q, %q), want (%q, %q)", tc.url, host, dir, tc.host, tc.dir)
		}
	}
}

// TestOpIsResolved pins which statuses are exempt from folding.
func TestOpIsResolved(t *testing.T) {
	notResolved := []string{opstream.StatusPending, opstream.StatusSignaled, opstream.StatusChecking}
	for _, s := range notResolved {
		if opIsResolved(s) {
			t.Errorf("opIsResolved(%q) = true, want false (must not fold)", s)
		}
	}
	resolved := []string{"200", "403", "502", opstream.StatusDenied, opstream.StatusError, opstream.StatusRunning, opstream.StatusTLSFailed}
	for _, s := range resolved {
		if !opIsResolved(s) {
			t.Errorf("opIsResolved(%q) = false, want true (eligible to fold)", s)
		}
	}
}

func countOf(d []DisplayedOp) int {
	if len(d) == 0 {
		return 0
	}
	return d[0].Count
}

// TestDisplayedOps_ConnectOpsFoldByHost — CONNECT ops are recorded
// scheme-less (a bare host or host:port with no path). They fold by
// exact host; CONNECTs to different hosts stay separate.
func TestDisplayedOps_ConnectOpsFoldByHost(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			{RequestID: "1", Method: "CONNECT", URL: "api.github.com", Status: "200", UpdatedAt: t0},
			{RequestID: "2", Method: "CONNECT", URL: "api.github.com", Status: "200", UpdatedAt: t0.Add(time.Second)},
			{RequestID: "3", Method: "CONNECT", URL: "files.example.com:8443", Status: "200", UpdatedAt: t0.Add(2 * time.Second)},
		},
	}
	got := DisplayedOps(m)
	if len(got) != 2 {
		t.Fatalf("groups len = %d, want 2 (two CONNECT api.github.com fold; the other host stays separate)", len(got))
	}
}

// TestApply_OpsTickPreservesSelectionAcrossRepresentativeFlip pins
// #119's selection-stability requirement: when a newer op joins a
// folded group its representative (and RequestID) changes, but the
// operator's cursor must stay on that group's row. The wider #119
// grouping key makes representative flips common — a burst of similar
// URLs is the feature's motivating scenario — and losing the cursor
// on every tick would make the feature unusable in exactly that case.
func TestApply_OpsTickPreservesSelectionAcrossRepresentativeFlip(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Cols: 100, Rows: 30,
		Ops: []opstream.Op{
			{RequestID: "solo", Method: "GET", URL: "https://other.example/z/1", Status: "200", UpdatedAt: t0.Add(10 * time.Second)},
			{RequestID: "g-old", Method: "GET", URL: "https://files.example/build/a", Status: "200", UpdatedAt: t0.Add(2 * time.Second)},
			{RequestID: "g-mid", Method: "GET", URL: "https://files.example/build/b", Status: "200", UpdatedAt: t0.Add(time.Second)},
		},
		Selected: 1, // the folded files.example/build/ group
	}
	if d := DisplayedOps(m); len(d) != 2 || d[1].RequestID != "g-old" || d[1].Count != 2 {
		t.Fatalf("setup: displayed = %+v, want row 1 = folded group rep g-old count 2", d)
	}
	// Tick: a newer op joins the files.example/build/ group, flipping
	// the representative from g-old to g-new.
	got, _ := Apply(m, OpsTickResult{Ops: []opstream.Op{
		{RequestID: "solo", Method: "GET", URL: "https://other.example/z/1", Status: "200", UpdatedAt: t0.Add(10 * time.Second)},
		{RequestID: "g-new", Method: "GET", URL: "https://files.example/build/c", Status: "200", UpdatedAt: t0.Add(5 * time.Second)},
		{RequestID: "g-old", Method: "GET", URL: "https://files.example/build/a", Status: "200", UpdatedAt: t0.Add(2 * time.Second)},
		{RequestID: "g-mid", Method: "GET", URL: "https://files.example/build/b", Status: "200", UpdatedAt: t0.Add(time.Second)},
	}})
	d := DisplayedOps(got)
	if got.Selected < 0 || got.Selected >= len(d) {
		t.Fatalf("Selected = %d out of range (len %d)", got.Selected, len(d))
	}
	sel := d[got.Selected]
	if sel.RequestID != "g-new" {
		t.Errorf("after representative flip, selected row RequestID = %q, want g-new (cursor must follow the group)", sel.RequestID)
	}
	if sel.Count != 3 {
		t.Errorf("selected group Count = %d, want 3", sel.Count)
	}
}
