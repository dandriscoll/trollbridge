package oplog

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in     string
		want   slog.Level
		wantOK bool
	}{
		{"", slog.LevelInfo, true},
		{"debug", slog.LevelDebug, true},
		{"DEBUG", slog.LevelDebug, true},
		{"  Info ", slog.LevelInfo, true},
		{"warn", slog.LevelWarn, true},
		{"warning", slog.LevelWarn, true},
		{"error", slog.LevelError, true},
		{"trace", 0, false},
		{"verbose", 0, false},
	}
	for _, c := range cases {
		got, err := ParseLevel(c.in)
		if c.wantOK && err != nil {
			t.Errorf("ParseLevel(%q): unexpected error: %v", c.in, err)
		}
		if !c.wantOK && err == nil {
			t.Errorf("ParseLevel(%q): expected error, got %v", c.in, got)
		}
		if c.wantOK && got != c.want {
			t.Errorf("ParseLevel(%q): got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseLevel_BadInputErrorMentionsValidSet(t *testing.T) {
	_, err := ParseLevel("trace")
	if err == nil {
		t.Fatal("expected error")
	}
	for _, sub := range []string{"debug", "info", "warn", "error"} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error missing %q: %v", sub, err)
		}
	}
}

func TestNew_StderrSinkSentinel(t *testing.T) {
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)
	lg, err := New(StderrSink, lv)
	if err != nil {
		t.Fatal(err)
	}
	if lg == nil {
		t.Fatal("nil logger")
	}
}

func TestNew_FileSinkOpensWithDirAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "op.log")
	lv := new(slog.LevelVar)
	lg, err := New(path, lv)
	if err != nil {
		t.Fatal(err)
	}
	lg.Info("hello", "k", "v")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", info.Mode().Perm())
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if parent.Mode().Perm() != 0o750 {
		t.Errorf("parent mode = %v, want 0750", parent.Mode().Perm())
	}
}

func TestNew_FailsClosedOnUnwritableParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses perm check")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	path := filepath.Join(dir, "newdir", "op.log")
	if _, err := New(path, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestHandler_FormatGoldenLine(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)
	h := &textHandler{dest: &sharedWriter{w: &buf}, level: lv}
	lg := slog.New(h)
	lg.Info("rules reloaded", "version", "abc123", "count", 5)

	got := buf.String()
	for _, sub := range []string{
		"INFO",
		"trollbridge: rules reloaded",
		"version=abc123",
		"count=5",
	} {
		if !strings.Contains(got, sub) {
			t.Errorf("output %q missing %q", got, sub)
		}
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("output missing trailing newline: %q", got)
	}
	// Spaces in values must be quoted.
	buf.Reset()
	lg.Info("oops", "msg", "two words")
	if !strings.Contains(buf.String(), `msg="two words"`) {
		t.Errorf("expected quoted value, got %q", buf.String())
	}
}

func TestHandler_LevelFilter(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelWarn)
	h := &textHandler{dest: &sharedWriter{w: &buf}, level: lv}
	lg := slog.New(h)
	lg.Debug("d")
	lg.Info("i")
	lg.Warn("w")
	lg.Error("e")
	out := buf.String()
	if strings.Contains(out, " DEBUG ") || strings.Contains(out, " INFO ") {
		t.Errorf("warn-level handler emitted lower level: %q", out)
	}
	if !strings.Contains(out, " WARN ") || !strings.Contains(out, " ERROR ") {
		t.Errorf("warn-level handler missing warn/error: %q", out)
	}
	// Mutate the level at runtime — debug should now flow.
	buf.Reset()
	lv.Set(slog.LevelDebug)
	lg.Debug("d2")
	if !strings.Contains(buf.String(), "trollbridge: d2") {
		t.Errorf("level mutation did not take effect: %q", buf.String())
	}
}

func TestHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)
	h := &textHandler{dest: &sharedWriter{w: &buf}, level: lv}
	lg := slog.New(h).With("request_id", "rid-123", "identity", "alice")
	lg.Info("forwarded", "host", "example.com")
	out := buf.String()
	for _, sub := range []string{"request_id=rid-123", "identity=alice", "host=example.com"} {
		if !strings.Contains(out, sub) {
			t.Errorf("missing %q in %q", sub, out)
		}
	}
}

// TestSwapWriter_AppliesToDerivedHandlers pins #56's contract: when
// the TUI redirects oplog away from stderr, derived per-request
// loggers (built via With) must follow. The textHandler shares a
// *sharedWriter across all WithAttrs copies so a single Swap
// retargets every derived handler.
func TestSwapWriter_AppliesToDerivedHandlers(t *testing.T) {
	first, err := New(StderrSink, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sub := first.With("request_id", "rid-XYZ")

	var buf bytes.Buffer
	if !SwapWriter(first, &buf) {
		t.Fatalf("SwapWriter returned false")
	}

	first.Info("root-event", "k", "v")
	sub.Info("sub-event", "k2", "v2")

	out := buf.String()
	if !strings.Contains(out, "root-event") {
		t.Errorf("root logger write did not land in new sink: %q", out)
	}
	if !strings.Contains(out, "sub-event") || !strings.Contains(out, "request_id=rid-XYZ") {
		t.Errorf("derived logger did not follow swap: %q", out)
	}
}

func TestHandler_EnabledRespectsContextSignature(t *testing.T) {
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)
	h := &textHandler{dest: nil, level: lv}
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Errorf("debug should be disabled at info level")
	}
	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Errorf("info should be enabled at info level")
	}
}
