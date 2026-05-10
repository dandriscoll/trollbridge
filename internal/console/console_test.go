package console

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimalV2Yaml writes a v2 trollbridge.yaml in dir with the given
// allow/deny seed entries. Returns the file path.
func minimalV2Yaml(t *testing.T, allowSeed, denySeed []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "trollbridge.yaml")
	var b strings.Builder
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

// runLines drives Backend.Execute for each input line and returns
// captured stdout plus the cumulative quit signal.
func runLines(t *testing.T, b *Backend, lines ...string) (string, bool) {
	t.Helper()
	var out bytes.Buffer
	quit := false
	for _, l := range lines {
		if b.Execute(&out, l) {
			quit = true
			break
		}
	}
	return out.String(), quit
}

// listsOf reads the yaml back and returns its allow/deny entries.
func listsOf(t *testing.T, path string) (allow, deny []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
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

func TestBackend_AllowAddsToFile(t *testing.T) {
	cfgPath := minimalV2Yaml(t, []string{"existing.example"}, nil)
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true}
	out, _ := runLines(t, b, "allow new.example")
	if !strings.Contains(out, "added new.example") {
		t.Errorf("expected confirmation; got: %s", out)
	}
	allow, _ := listsOf(t, cfgPath)
	if !contains(allow, "new.example") {
		t.Errorf("file did not receive entry: %v", allow)
	}
}

func TestBackend_AllowRejectsBadPattern(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true}
	out, _ := runLines(t, b, "allow api.*.foo")
	if !strings.Contains(out, "invalid pattern") {
		t.Errorf("expected invalid-pattern error; got: %s", out)
	}
	allow, _ := listsOf(t, cfgPath)
	if len(allow) != 0 {
		t.Errorf("allow list should not have grown: %v", allow)
	}
}

func TestBackend_AllowResultIsSorted(t *testing.T) {
	cfgPath := minimalV2Yaml(t, []string{"z.example.com", "a.example.com"}, nil)
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true}
	runLines(t, b, "allow m.example.com")
	allow, _ := listsOf(t, cfgPath)
	want := []string{"a.example.com", "m.example.com", "z.example.com"}
	if !equal(allow, want) {
		t.Errorf("got %v, want %v", allow, want)
	}
}

func TestBackend_DenyAddsToFile(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true}
	out, _ := runLines(t, b, "deny pastebin.com")
	if !strings.Contains(out, "added pastebin.com") {
		t.Errorf("expected deny confirmation; got: %s", out)
	}
	_, deny := listsOf(t, cfgPath)
	if !contains(deny, "pastebin.com") {
		t.Errorf("deny did not receive entry: %v", deny)
	}
}

func TestBackend_RemoveDropsFromBothLists(t *testing.T) {
	cfgPath := minimalV2Yaml(t, []string{"a.example", "b.example"}, []string{"a.example"})
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true}
	out, _ := runLines(t, b, "remove a.example")
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

func TestBackend_ListPrintsCurrentEntries(t *testing.T) {
	cfgPath := minimalV2Yaml(t, []string{"x.example"}, []string{"y.example"})
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true}
	out, _ := runLines(t, b, "list all")
	if !strings.Contains(out, "x.example") || !strings.Contains(out, "y.example") {
		t.Errorf("list missing entries: %s", out)
	}
}

func TestBackend_HelpLocal(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true}
	out, _ := runLines(t, b, "help")
	for _, k := range []string{"allow", "deny", "remove", "list", "help"} {
		if !strings.Contains(out, k) {
			t.Errorf("help missing %q: %s", k, out)
		}
	}
}

func TestBackend_HelpRemoteAttachOnly(t *testing.T) {
	b := &Backend{LocalOnly: false}
	out, _ := runLines(t, b, "help")
	if !strings.Contains(out, "attach mode") {
		t.Errorf("attach-mode help missing 'attach mode' label: %s", out)
	}
	if strings.Contains(out, "lists.allow") {
		t.Errorf("attach-mode help should not mention list editing: %s", out)
	}
}

func TestBackend_UnknownCommand(t *testing.T) {
	b := &Backend{LocalOnly: true}
	out, _ := runLines(t, b, "frob")
	if !strings.Contains(out, "unknown command") {
		t.Errorf("expected unknown-command message; got: %s", out)
	}
}

func TestBackend_QuitReturnsTrue(t *testing.T) {
	b := &Backend{LocalOnly: true}
	_, quit := runLines(t, b, "quit")
	if !quit {
		t.Errorf("quit did not return true")
	}
}

func TestBackend_EmptyLineNoOp(t *testing.T) {
	b := &Backend{LocalOnly: true}
	out, _ := runLines(t, b, "", "  ")
	if out != "" {
		t.Errorf("empty input produced output: %q", out)
	}
}

func TestBackend_TestDispatchesToCallback(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	called := ""
	b := &Backend{
		ConfigPath: cfgPath,
		LocalOnly:  true,
		OnTest: func(out io.Writer, urlArg string) error {
			called = urlArg
			_, _ = out.Write([]byte("(callback ran)\n"))
			return nil
		},
	}
	out, _ := runLines(t, b, "test https://example.com")
	if called != "https://example.com" {
		t.Errorf("OnTest got urlArg=%q", called)
	}
	if !strings.Contains(out, "(callback ran)") {
		t.Errorf("expected callback output: %s", out)
	}
}

func TestBackend_TestNoArgPrintsUsage(t *testing.T) {
	b := &Backend{LocalOnly: true, OnTest: func(io.Writer, string) error {
		t.Fatalf("OnTest should not fire for empty url")
		return nil
	}}
	out, _ := runLines(t, b, "test")
	if !strings.Contains(out, "usage: test") {
		t.Errorf("expected usage hint: %s", out)
	}
}

func TestBackend_TestNotWired(t *testing.T) {
	b := &Backend{LocalOnly: true}
	out, _ := runLines(t, b, "test https://x/")
	if !strings.Contains(out, "test: not wired") {
		t.Errorf("expected 'not wired': %s", out)
	}
}

func TestBackend_DoctorDispatchesToCallback(t *testing.T) {
	called := false
	b := &Backend{LocalOnly: true, OnDoctor: func(out io.Writer) error {
		called = true
		_, _ = out.Write([]byte("(doctor ran)\n"))
		return nil
	}}
	out, _ := runLines(t, b, "doctor")
	if !called {
		t.Errorf("OnDoctor not fired: %s", out)
	}
	if !strings.Contains(out, "(doctor ran)") {
		t.Errorf("expected doctor output: %s", out)
	}
}

func TestBackend_TestPanicRecovers(t *testing.T) {
	b := &Backend{LocalOnly: true, OnTest: func(io.Writer, string) error {
		panic("boom")
	}}
	out, _ := runLines(t, b, "test https://x/")
	if !strings.Contains(out, "test: panic: boom") {
		t.Errorf("expected panic banner: %s", out)
	}
}

func TestBackend_AttachModeBlocksLocalCommands(t *testing.T) {
	b := &Backend{LocalOnly: false}
	for _, cmd := range []string{"allow x.example", "deny y.example", "remove z.example", "list", "reload", "test https://x/", "doctor"} {
		out, _ := runLines(t, b, cmd)
		if !strings.Contains(out, "not available in attach mode") {
			t.Errorf("attach-mode %q missing gate hint: %s", cmd, out)
		}
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
