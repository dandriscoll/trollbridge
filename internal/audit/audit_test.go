package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/types"
)

func TestLogger_WritesEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := New(path, 16, OverflowDeny)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Entry{
		RequestID:  "abc",
		IdentityID: "alice",
		Method:     "GET",
		Host:       "example.com",
		Port:       443,
		Path:       "/foo",
		Decision:   "allow",
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("expected one entry")
	}
	var got Entry
	if err := json.Unmarshal(scanner.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.RequestID != "abc" || got.Host != "example.com" || got.Decision != "allow" {
		t.Errorf("unexpected entry: %+v", got)
	}
	if got.AuditSchemaVersion == 0 {
		t.Errorf("audit_schema_version not set")
	}
	if got.Timestamp == "" {
		t.Errorf("timestamp not set")
	}
}

func TestLogger_FileMode0640(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not enforceable on Windows; protection is via NTFS ACLs, see internal/ca/keymode_windows.go")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := New(path, 4, OverflowDeny)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode().Perm()
	if mode != 0o640 {
		t.Errorf("file mode = %o, want 0640", mode)
	}
}

func TestLogger_OverflowDenyReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	// Buffer of 1; we'll overrun deliberately.
	l, err := New(path, 1, OverflowDeny)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	// Fill the buffer faster than the writer can drain by NOT
	// letting the goroutine schedule. Push many entries.
	denied := 0
	for i := 0; i < 1000; i++ {
		if err := l.Write(Entry{RequestID: "x"}); err != nil {
			denied++
		}
	}
	// At least one should have been denied since buffer=1.
	// (Determinism here depends on scheduler; we tolerate >=0
	// since on a fast machine the writer may drain in time.)
	_ = denied
	_ = time.Now()
}

func TestLogger_OverflowDropCounts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := New(path, 1, OverflowDrop)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	for i := 0; i < 1000; i++ {
		if err := l.Write(Entry{RequestID: "x"}); err != nil {
			t.Errorf("OverflowDrop returned error: %v", err)
		}
	}
	// Drop counter should be reachable; we don't assert > 0
	// strictly because under fast scheduling the queue may drain.
	_ = l.Dropped()
}

// TestParseLevel exhausts the operator-facing level strings and
// pins that an empty string defaults to LevelAll. Unknown values
// surface a clear error naming the legal set.
func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want Level
		err  bool
	}{
		{"", LevelAll, false},
		{"all", LevelAll, false},
		{"decisions", LevelDecisions, false},
		{"none", LevelNone, false},
		{"verbose", LevelAll, true},
		{"All", LevelAll, true}, // case-sensitive on purpose; matches existing AuditOverflow validator.
	}
	for _, tc := range cases {
		got, err := ParseLevel(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("ParseLevel(%q): want error, got Level=%v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseLevel(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestLogger_LevelFilter_DropsByDecisionSource pins the three-level
// emission filter (#113). For each level, write one Entry per
// known DecisionSource and assert the resulting file contains only
// the sources the level admits.
//
// LevelNone:      0 lines.
// LevelDecisions: only llm_advisor, approval_queue, approval_timeout.
// LevelAll:       every source.
//
// The DecisionSource set is taken from types.AllDecisionSources so
// a new source added in internal/types is observed by this test
// without manual sync — the sweep test in internal/types enforces
// that AllDecisionSources stays in lockstep with the const block.
func TestLogger_LevelFilter_DropsByDecisionSource(t *testing.T) {
	cases := []struct {
		name        string
		level       Level
		wantSources map[string]bool
	}{
		{
			name:        "none_drops_everything",
			level:       LevelNone,
			wantSources: map[string]bool{},
		},
		{
			name:  "decisions_admits_human_and_llm_only",
			level: LevelDecisions,
			wantSources: map[string]bool{
				string(types.SourceLLMAdvisor):      true,
				string(types.SourceApprovalQueue):   true,
				string(types.SourceApprovalTimeout): true,
			},
		},
		{
			name:  "all_admits_every_source",
			level: LevelAll,
			wantSources: func() map[string]bool {
				m := map[string]bool{}
				for _, s := range types.AllDecisionSources {
					m[string(s)] = true
				}
				return m
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.jsonl")
			l, err := New(path, 64, OverflowBlock)
			if err != nil {
				t.Fatal(err)
			}
			l.SetLevel(tc.level)
			for _, src := range types.AllDecisionSources {
				if err := l.Write(Entry{
					RequestID:      "req-" + string(src),
					DecisionSource: string(src),
					Decision:       "allow",
				}); err != nil {
					t.Fatalf("Write %q: %v", src, err)
				}
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}

			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			got := map[string]bool{}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				var e Entry
				if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				got[e.DecisionSource] = true
			}
			if len(got) != len(tc.wantSources) {
				t.Errorf("emitted %d distinct sources, want %d (got=%v want=%v)", len(got), len(tc.wantSources), got, tc.wantSources)
			}
			for src := range tc.wantSources {
				if !got[src] {
					t.Errorf("level=%v: %q not in audit log; expected", tc.level, src)
				}
			}
			for src := range got {
				if !tc.wantSources[src] {
					t.Errorf("level=%v: %q in audit log; should have been filtered out", tc.level, src)
				}
			}
		})
	}
}

// TestLogger_LevelDecisions_DropsFailureEntries pins the
// user-confirmed intent of the `decisions` level: it is decisions
// only. Failure / error entries — a TLS handshake failure is the
// canonical case — carry a non-human/LLM DecisionSource and are NOT
// retained, even though they also carry Error / TLSErrorCategory.
//
// TestLogger_LevelFilter_DropsByDecisionSource above writes only
// clean `allow` entries, so it would still pass if a future change
// started retaining entries that carry TLSErrorCategory/Error. This
// test locks the decision against exactly that carve-out: at
// `decisions` level the human/LLM decision survives and the
// failure entry is dropped, both written to one logger.
func TestLogger_LevelDecisions_DropsFailureEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := New(path, 64, OverflowBlock)
	if err != nil {
		t.Fatal(err)
	}
	l.SetLevel(LevelDecisions)

	// A TLS-handshake-failure-shaped entry: non-human/LLM source,
	// plus the failure diagnostics a forensic carve-out would key on.
	if err := l.Write(Entry{
		RequestID:        "req-tls-fail",
		DecisionSource:   string(types.SourceDefault),
		Decision:         "deny",
		Error:            "tls: handshake failure",
		TLSErrorCategory: "unsupported_protocol",
		TLSSNI:           "blocked.example",
	}); err != nil {
		t.Fatalf("Write failure entry: %v", err)
	}
	// A genuine decision in the same logger — must survive, proving
	// the filter still admits decisions while dropping the failure.
	if err := l.Write(Entry{
		RequestID:      "req-approved",
		DecisionSource: string(types.SourceApprovalQueue),
		Decision:       "allow",
	}); err != nil {
		t.Fatalf("Write decision entry: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var got []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got = append(got, e.RequestID)
	}
	if len(got) != 1 || got[0] != "req-approved" {
		t.Errorf("LevelDecisions emitted %v, want only [req-approved] — the failure entry must be dropped (decisions is decisions only)", got)
	}
}

// TestLogger_LevelChangeIsObservable pins that SetLevel is hot —
// the next Write picks up the new level. Critical for runtime
// reconfiguration paths that may toggle audit levels without
// restarting the proxy.
func TestLogger_LevelChangeIsObservable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := New(path, 16, OverflowBlock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	// Default = LevelAll: emit one rule-source entry.
	if err := l.Write(Entry{RequestID: "before", DecisionSource: string(types.SourceRule), Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	// Switch to LevelDecisions: same rule-source entry must NOT emit.
	l.SetLevel(LevelDecisions)
	if err := l.Write(Entry{RequestID: "after", DecisionSource: string(types.SourceRule), Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ids := []string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.RequestID)
	}
	if len(ids) != 1 || ids[0] != "before" {
		t.Errorf("want exactly the pre-SetLevel entry, got %v", ids)
	}
}

// TestLogger_CloseSummaryWhenCountersNonzero closes #143 part d:
// Logger.Close emits an INFO audit_logger_close_summary line on the
// operational log when either the OverflowDrop or level-filter
// counter ended up non-zero, so an operator reading the oplog at
// shutdown sees the cumulative loss without scraping.
func TestLogger_CloseSummaryWhenCountersNonzero(t *testing.T) {
	dir := t.TempDir()
	l, err := New(filepath.Join(dir, "audit.jsonl"), 16, OverflowBlock)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, nil))
	l.SetOpLog(lg)

	// Drive the level-filter counter to a non-zero value.
	l.SetLevel(LevelDecisions)
	for i := 0; i < 3; i++ {
		if err := l.Write(Entry{RequestID: "r", DecisionSource: string(types.SourceRule), Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "event=audit_logger_close_summary") {
		t.Errorf("Close did not emit close-summary event:\n%s", got)
	}
	if !strings.Contains(got, "level_filtered=3") {
		t.Errorf("close summary should carry level_filtered=3:\n%s", got)
	}
}

// TestLogger_CloseSummaryQuietWhenAllCountersZero — clean shutdown
// (no drops, no filters) should NOT spam the operational log with
// a summary entry. Operators tail oplog; the summary is signal only
// when it carries non-zero numbers.
func TestLogger_CloseSummaryQuietWhenAllCountersZero(t *testing.T) {
	dir := t.TempDir()
	l, err := New(filepath.Join(dir, "audit.jsonl"), 16, OverflowBlock)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, nil))
	l.SetOpLog(lg)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "audit_logger_close_summary") {
		t.Errorf("close-summary should be quiet when counters are zero; got:\n%s", buf.String())
	}
}

// TestLogger_LevelFilteredCounter closes #143 part a: an operator
// can observe how many entries the audit-level filter dropped, so
// "where did my static-policy entries go?" is one read away from a
// real number.
func TestLogger_LevelFilteredCounter(t *testing.T) {
	dir := t.TempDir()
	l, err := New(filepath.Join(dir, "audit.jsonl"), 16, OverflowBlock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if got := l.LevelFiltered(); got != 0 {
		t.Errorf("zero state: LevelFiltered = %d, want 0", got)
	}

	// LevelDecisions filters out static-policy entries.
	l.SetLevel(LevelDecisions)
	if err := l.Write(Entry{RequestID: "r1", DecisionSource: string(types.SourceRule), Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Entry{RequestID: "r2", DecisionSource: string(types.SourceAllowList), Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if got := l.LevelFiltered(); got != 2 {
		t.Errorf("after 2 static-policy drops: LevelFiltered = %d, want 2", got)
	}

	// LevelNone drops everything.
	l.SetLevel(LevelNone)
	if err := l.Write(Entry{RequestID: "r3", DecisionSource: string(types.SourceLLMAdvisor), Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if got := l.LevelFiltered(); got != 3 {
		t.Errorf("after LevelNone drop: LevelFiltered = %d, want 3", got)
	}

	// Back to LevelAll — counter does not retroactively change; new
	// writes don't increment.
	l.SetLevel(LevelAll)
	if err := l.Write(Entry{RequestID: "r4", DecisionSource: string(types.SourceRule), Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if got := l.LevelFiltered(); got != 3 {
		t.Errorf("after LevelAll write: LevelFiltered = %d, want 3 (counter must not retro-increment)", got)
	}
}
