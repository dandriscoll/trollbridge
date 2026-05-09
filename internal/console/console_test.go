package console

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// minimalV2Yaml writes a v2 trollbridge.yaml in dir with the given
// allow/deny seed entries. Returns the file path.
func minimalV2Yaml(t *testing.T, allowSeed, denySeed []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "trollbridge.yaml")
	var b strings.Builder
	b.WriteString("trollbridge_version: 3\n")
	b.WriteString("proxy: lo:8080\n")
	b.WriteString("control: lo:8081\n")
	b.WriteString("controller: {auth: mtls}\n")
	b.WriteString("mode: default-deny\n")
	b.WriteString("logging: {audit_path: /tmp/audit.jsonl}\n")
	b.WriteString("lists:\n  allow:\n")
	for _, e := range allowSeed {
		b.WriteString("    - " + e + "\n")
	}
	b.WriteString("  deny:\n")
	for _, e := range denySeed {
		b.WriteString("    - " + e + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runWith drives the REPL against a v2 trollbridge.yaml and returns
// captured stdout.
func runWith(t *testing.T, configPath, input string) string {
	t.Helper()
	in := strings.NewReader(input)
	var out bytes.Buffer
	cfg := Config{
		ConfigPath: configPath,
		In:         in,
		Out:        &out,
		Prompt:     "> ",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Run(ctx, cfg); err != nil && err != io.EOF {
		t.Fatalf("Run: %v", err)
	}
	return out.String()
}

// runWithCallbacks is like runWith but lets the test inject the
// new OnTest / OnDoctor callbacks (issue #31). Returns captured stdout.
func runWithCallbacks(t *testing.T, configPath, input string,
	onTest func(io.Writer, string) error, onDoctor func(io.Writer) error) string {
	t.Helper()
	var out bytes.Buffer
	cfg := Config{
		ConfigPath: configPath,
		In:         strings.NewReader(input),
		Out:        &out,
		Prompt:     "> ",
		OnTest:     onTest,
		OnDoctor:   onDoctor,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Run(ctx, cfg); err != nil && err != io.EOF {
		t.Fatalf("Run: %v", err)
	}
	return out.String()
}

// listsOf reads the yaml back and returns its allow/deny entries.
func listsOf(t *testing.T, path string) (allow, deny []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Tiny ad-hoc parser: scan for `  - X` entries under the
	// matching parent key. Sufficient for these tests; we don't
	// re-import the full config package to keep this isolated.
	lines := strings.Split(string(data), "\n")
	var section string
	for _, l := range lines {
		switch strings.TrimSpace(l) {
		case "allow:":
			if strings.HasPrefix(l, "  ") {
				section = "allow"
			}
			continue
		case "deny:":
			if strings.HasPrefix(l, "  ") {
				section = "deny"
			}
			continue
		}
		if !strings.HasPrefix(l, "    - ") {
			if l != "" && !strings.HasPrefix(l, "    ") && !strings.HasPrefix(l, "      ") {
				section = ""
			}
			continue
		}
		entry := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "-"))
		switch section {
		case "allow":
			allow = append(allow, entry)
		case "deny":
			deny = append(deny, entry)
		}
	}
	return
}

func TestConsole_AllowAddsToFile(t *testing.T) {
	cfgPath := minimalV2Yaml(t, []string{"existing.example"}, nil)
	out := runWith(t, cfgPath, "allow new.example\nquit\n")
	if !strings.Contains(out, "added new.example") {
		t.Errorf("expected confirmation; got: %s", out)
	}
	allow, _ := listsOf(t, cfgPath)
	if !contains(allow, "new.example") {
		t.Errorf("file did not receive entry: %v", allow)
	}
}

func TestConsole_AllowRejectsBadPattern(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	out := runWith(t, cfgPath, "allow api.*.foo\nquit\n")
	if !strings.Contains(out, "invalid pattern") {
		t.Errorf("expected invalid-pattern error; got: %s", out)
	}
	allow, _ := listsOf(t, cfgPath)
	if len(allow) != 0 {
		t.Errorf("allow list should not have grown: %v", allow)
	}
}

func TestConsole_AllowResultIsSorted(t *testing.T) {
	cfgPath := minimalV2Yaml(t, []string{"z.example.com", "a.example.com"}, nil)
	runWith(t, cfgPath, "allow m.example.com\nquit\n")
	allow, _ := listsOf(t, cfgPath)
	want := []string{"a.example.com", "m.example.com", "z.example.com"}
	if !equal(allow, want) {
		t.Errorf("got %v, want %v", allow, want)
	}
}

func TestConsole_DenyAddsToFile(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	out := runWith(t, cfgPath, "deny pastebin.com\nquit\n")
	if !strings.Contains(out, "added pastebin.com") {
		t.Errorf("expected deny confirmation; got: %s", out)
	}
	_, deny := listsOf(t, cfgPath)
	if !contains(deny, "pastebin.com") {
		t.Errorf("deny did not receive entry: %v", deny)
	}
}

func TestConsole_RemoveDropsFromBothLists(t *testing.T) {
	cfgPath := minimalV2Yaml(t, []string{"a.example", "b.example"}, []string{"a.example"})
	out := runWith(t, cfgPath, "remove a.example\nquit\n")
	if !strings.Contains(out, "removed a.example") {
		t.Errorf("expected remove confirmation; got: %s", out)
	}
	allow, deny := listsOf(t, cfgPath)
	if contains(allow, "a.example") {
		t.Errorf("a.example still in allow: %v", allow)
	}
	if contains(deny, "a.example") {
		t.Errorf("a.example still in deny: %v", deny)
	}
}

func TestConsole_ListPrintsCurrentEntries(t *testing.T) {
	cfgPath := minimalV2Yaml(t, []string{"x.example"}, []string{"y.example"})
	out := runWith(t, cfgPath, "list all\nquit\n")
	if !strings.Contains(out, "x.example") || !strings.Contains(out, "y.example") {
		t.Errorf("list missing entries: %s", out)
	}
}

func TestConsole_HelpIsAvailable(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	out := runWith(t, cfgPath, "help\nquit\n")
	for _, k := range []string{"allow", "deny", "remove", "list", "help"} {
		if !strings.Contains(out, k) {
			t.Errorf("help missing %q: %s", k, out)
		}
	}
}

func TestConsole_UnknownCommandPrintsError(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	out := runWith(t, cfgPath, "frob\nquit\n")
	if !strings.Contains(out, "unknown command") {
		t.Errorf("expected unknown-command message; got: %s", out)
	}
}

func TestConsole_QuitExitsCleanly(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	in := strings.NewReader("quit\n")
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Run(ctx, Config{ConfigPath: cfgPath, In: in, Out: &out}); err != nil {
		t.Fatal(err)
	}
}

// TestREPL_TestCommand_DispatchesToCallback closes issue #31:
// `test <url>` at the prompt should hand off to OnTest with the
// URL argument. The callback's output appears in the same stream.
func TestREPL_TestCommand_DispatchesToCallback(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	called := ""
	onTest := func(out io.Writer, urlArg string) error {
		called = urlArg
		_, _ = out.Write([]byte("(callback ran)\n"))
		return nil
	}
	out := runWithCallbacks(t, cfgPath, "test https://example.com\nquit\n", onTest, nil)
	if called != "https://example.com" {
		t.Errorf("OnTest got urlArg=%q, want %q", called, "https://example.com")
	}
	if !strings.Contains(out, "(callback ran)") {
		t.Errorf("expected callback output in REPL stream:\n%s", out)
	}
}

// TestREPL_TestCommand_NoArg_PrintsUsage covers the empty-arg branch.
func TestREPL_TestCommand_NoArg_PrintsUsage(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	onTest := func(out io.Writer, urlArg string) error {
		t.Fatalf("OnTest should not fire for empty URL; got %q", urlArg)
		return nil
	}
	out := runWithCallbacks(t, cfgPath, "test\nquit\n", onTest, nil)
	if !strings.Contains(out, "usage: test") {
		t.Errorf("expected usage hint for `test` with no arg:\n%s", out)
	}
}

// TestREPL_TestCommand_NotWired hits the path where OnTest is nil.
func TestREPL_TestCommand_NotWired(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	out := runWithCallbacks(t, cfgPath, "test https://x/\nquit\n", nil, nil)
	if !strings.Contains(out, "test: not wired") {
		t.Errorf("expected 'not wired' message; got:\n%s", out)
	}
}

// TestREPL_DoctorCommand_DispatchesToCallback covers the doctor branch
// (per the user's follow-up comment on #31).
func TestREPL_DoctorCommand_DispatchesToCallback(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	called := false
	onDoctor := func(out io.Writer) error {
		called = true
		_, _ = out.Write([]byte("(doctor ran)\n"))
		return nil
	}
	out := runWithCallbacks(t, cfgPath, "doctor\nquit\n", nil, onDoctor)
	if !called {
		t.Errorf("OnDoctor never fired; out:\n%s", out)
	}
	if !strings.Contains(out, "(doctor ran)") {
		t.Errorf("expected doctor output:\n%s", out)
	}
}

// TestREPL_TestCommand_PanicRecovers proves the recover() path keeps
// the REPL alive after a callback panic — we get the panic banner
// printed and the prompt comes back.
func TestREPL_TestCommand_PanicRecovers(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	onTest := func(out io.Writer, urlArg string) error {
		panic("boom")
	}
	out := runWithCallbacks(t, cfgPath, "test https://x/\nquit\n", onTest, nil)
	if !strings.Contains(out, "test: panic: boom") {
		t.Errorf("expected panic banner; got:\n%s", out)
	}
}

func contains(xs []string, target string) bool {
	for _, x := range xs {
		if x == target {
			return true
		}
	}
	return false
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
