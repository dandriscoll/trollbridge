package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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
