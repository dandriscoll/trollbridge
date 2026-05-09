package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/ca"
)

// withStubbedBootstrapCA replaces the package-level bootstrapCA
// var with a recorder for the duration of the test. Returns a
// pointer the test can read to confirm the stub was called with
// the expected paths.
type bootstrapCall struct {
	certPath, keyPath string
	force             bool
	called            bool
}

func withStubbedBootstrapCA(t *testing.T) *bootstrapCall {
	t.Helper()
	rec := &bootstrapCall{}
	prev := bootstrapCA
	bootstrapCA = func(certPath, keyPath string, force bool) (*ca.CA, error) {
		rec.certPath = certPath
		rec.keyPath = keyPath
		rec.force = force
		rec.called = true
		// Return a real (small) CA so SHA256Fingerprint() works in
		// the next-steps output.
		return ca.Init(certPath, keyPath, ca.KeyTypeECDSAP256, force)
	}
	t.Cleanup(func() { bootstrapCA = prev })
	return rec
}

func TestApplyAnswers_LaptopDefaults(t *testing.T) {
	out := applyAnswers(defaultConfigYAML, initAnswers{
		topology: "laptop",
		mode:     "default-ask",
	})
	if out != defaultConfigYAML {
		t.Errorf("laptop + default-ask + no overrides should produce the static template byte-for-byte")
	}
}

func TestApplyAnswers_VMTopologyAllBind(t *testing.T) {
	out := applyAnswers(defaultConfigYAML, initAnswers{
		topology: "incus-vm",
		mode:     "default-ask",
	})
	if !strings.Contains(out, "proxy:   all:8080") {
		t.Errorf("VM topology should bind on all:8080; got:\n%s", out)
	}
	if strings.Contains(out, "proxy:   lo:8080") {
		t.Errorf("VM topology must replace the lo:8080 default; got it still present")
	}
}

func TestApplyAnswers_HostDaemonAllBind(t *testing.T) {
	out := applyAnswers(defaultConfigYAML, initAnswers{
		topology: "host-daemon",
		mode:     "default-deny",
	})
	if !strings.Contains(out, "proxy:   all:8080") {
		t.Errorf("host-daemon topology should bind on all:8080; got:\n%s", out)
	}
	if !strings.Contains(out, "mode: default-deny") {
		t.Errorf("mode substitution missing; got:\n%s", out)
	}
}

func TestApplyAnswers_InterceptionEnabled(t *testing.T) {
	out := applyAnswers(defaultConfigYAML, initAnswers{
		topology:     "laptop",
		mode:         "default-ask",
		interception: true,
	})
	// The substitution targets the line under `interception:`. We
	// assert the surrounding context is preserved.
	if !strings.Contains(out, "interception:\n  enabled: true\n  ca:") {
		t.Errorf("interception toggle did not apply to the right block; got:\n%s", out)
	}
	if strings.Contains(out, "interception:\n  enabled: false") {
		t.Errorf("interception=true should have replaced the false default")
	}
}

func TestApplyAnswers_LLMEnabledWithProvider(t *testing.T) {
	out := applyAnswers(defaultConfigYAML, initAnswers{
		topology:    "laptop",
		mode:        "default-ask",
		llmEnabled:  true,
		llmProvider: "aoai",
		llmModel:    "gpt-4o",
		llmKeyPath:  "/var/secrets/aoai.key",
	})
	for _, want := range []string{
		"  enabled: true\n  provider: aoai",
		"  model:    gpt-4o",
		"  api_key_path: /var/secrets/aoai.key",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("LLM substitution missing %q in output:\n%s", want, out)
		}
	}
}

func TestPromptYesNo_RecognizesYNYesNo(t *testing.T) {
	cases := []struct {
		in   string
		def  bool
		want bool
	}{
		{"y\n", false, true},
		{"Y\n", false, true},
		{"yes\n", false, true},
		{"YES\n", false, true},
		{"n\n", true, false},
		{"no\n", true, false},
		{"\n", true, true},
		{"\n", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		t.Run(strings.TrimSpace(c.in), func(t *testing.T) {
			var buf bytes.Buffer
			r := newReader(c.in)
			got := promptYesNo(r, &buf, "x", c.def)
			if got != c.want {
				t.Errorf("promptYesNo(%q, def=%v) = %v, want %v", c.in, c.def, got, c.want)
			}
		})
	}
}

func TestPromptChoice_DefaultOnEmptyInput(t *testing.T) {
	var buf bytes.Buffer
	got := promptChoice(newReader("\n"), &buf, "x", []string{"a", "b", "c"}, "b")
	if got != "b" {
		t.Errorf("empty input should select default 'b'; got %q", got)
	}
}

func TestPromptChoice_RetriesOnUnknownChoice(t *testing.T) {
	var buf bytes.Buffer
	// First answer "zzz" (unknown), then "c" (valid).
	got := promptChoice(newReader("zzz\nc\n"), &buf, "x", []string{"a", "b", "c"}, "a")
	if got != "c" {
		t.Errorf("retry should pick the valid 'c'; got %q", got)
	}
	if !strings.Contains(buf.String(), "unknown choice") {
		t.Errorf("retry path should print an 'unknown choice' notice; got:\n%s", buf.String())
	}
}

func TestPromptSecret_RejectsEmpty(t *testing.T) {
	var buf bytes.Buffer
	// First answer empty, second answer empty too — abort.
	_, err := promptSecret(newReader("\n\n"), &buf, "key")
	if err == nil {
		t.Error("two empty inputs should produce an error")
	}
	// First answer empty, second answer non-empty — accept.
	got, err := promptSecret(newReader("\nsk-test\n"), &buf, "key")
	if err != nil {
		t.Fatalf("non-empty after retry should succeed: %v", err)
	}
	if got != "sk-test" {
		t.Errorf("got %q, want sk-test", got)
	}
}

func TestRunInteractiveInit_HappyPathAllOff(t *testing.T) {
	in := newReader(strings.Join([]string{
		"laptop",       // topology
		"default-deny", // mode
		"n",            // interception
		"n",            // advisor
		"",             // (no further input needed)
	}, "\n") + "\n")
	var out bytes.Buffer
	ans, err := runInteractiveInit(in, &out)
	if err != nil {
		t.Fatalf("runInteractiveInit: %v\n%s", err, out.String())
	}
	if ans.topology != "laptop" || ans.mode != "default-deny" || ans.interception || ans.llmEnabled {
		t.Errorf("answers mis-collected: %+v", ans)
	}
}

func TestInit_NonInteractiveFlagForcesStaticPath(t *testing.T) {
	dir := t.TempDir()
	cmd := newInitCmd()
	var out bytes.Buffer
	// Even on a TTY (which we can't easily simulate here), the flag
	// would force the static path. With a non-TTY stdin (the test
	// buffer), the result is the same — but we exercise the flag
	// to guard against future regressions.
	cmd.SetIn(newReader("garbage that should never be read"))
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-d", dir, "--non-interactive"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --non-interactive: %v\n%s", err, out.String())
	}
	body, err := os.ReadFile(filepath.Join(dir, "trollbridge.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != defaultConfigYAML {
		t.Errorf("--non-interactive should write the static template byte-for-byte")
	}
}

func TestInit_InteractiveInterceptionTriggersCABootstrap(t *testing.T) {
	rec := withStubbedBootstrapCA(t)
	dir := t.TempDir()

	// Use the stdinIsTTY seam: replace the global isTerminal var to
	// claim the test reader is a TTY. Restore on cleanup.
	prev := isTerminal
	isTerminal = func(int) bool { return true }
	t.Cleanup(func() { isTerminal = prev })

	// We need cmd.InOrStdin() to return an *os.File (so stdinIsTTY's
	// type assertion succeeds). A pipe gives us that.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = pr.Close() })
	go func() {
		defer pw.Close()
		_, _ = pw.WriteString(strings.Join([]string{
			"laptop",
			"default-deny",
			"y", // interception=on
			"n", // advisor=off
		}, "\n") + "\n")
	}()

	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetIn(pr)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-d", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init interactive: %v\n%s", err, out.String())
	}

	if !rec.called {
		t.Fatalf("bootstrapCA was not called; output:\n%s", out.String())
	}
	wantCert := filepath.Join(dir, "trollbridge-ca.crt")
	wantKey := filepath.Join(dir, "trollbridge-ca.key")
	if rec.certPath != wantCert || rec.keyPath != wantKey {
		t.Errorf("bootstrapCA called with %q/%q, want %q/%q", rec.certPath, rec.keyPath, wantCert, wantKey)
	}

	body, err := os.ReadFile(filepath.Join(dir, "trollbridge.yaml"))
	if err != nil {
		t.Fatalf("read yaml: %v", err)
	}
	if !strings.Contains(string(body), "  enabled: true\n  ca:") {
		t.Errorf("interception=on should appear in YAML; got:\n%s", body)
	}
	if !strings.Contains(string(body), "mode: default-deny") {
		t.Errorf("mode=default-deny should appear in YAML; got:\n%s", body)
	}
}

func TestInit_InteractiveLLMWritesKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "secrets", "llm.key") // includes a non-existent subdir
	keyValue := "sk-test-12345"

	prev := isTerminal
	isTerminal = func(int) bool { return true }
	t.Cleanup(func() { isTerminal = prev })

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = pr.Close() })
	go func() {
		defer pw.Close()
		_, _ = pw.WriteString(strings.Join([]string{
			"laptop",
			"default-ask",
			"n", // interception=off
			"y", // advisor=on
			"anthropic",
			"claude-opus-4-7",
			keyPath,
			keyValue,
		}, "\n") + "\n")
	}()

	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetIn(pr)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-d", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init interactive llm: %v\n%s", err, out.String())
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("LLM key file not written at %s: %v", keyPath, err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("LLM key mode = %o, want 0600", mode)
	}
	got, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(got) != keyValue {
		t.Errorf("LLM key contents = %q, want %q", string(got), keyValue)
	}

	body, err := os.ReadFile(filepath.Join(dir, "trollbridge.yaml"))
	if err != nil {
		t.Fatalf("read yaml: %v", err)
	}
	if !strings.Contains(string(body), "api_key_path: "+keyPath) {
		t.Errorf("YAML should reference the chosen key path; got:\n%s", body)
	}
	if !strings.Contains(string(body), "  enabled: true\n  provider: anthropic") {
		t.Errorf("YAML should reflect llm.enabled=true; got:\n%s", body)
	}
}

// newReader returns a *bufio.Reader over s. The prompt helpers
// take *bufio.Reader; runInteractiveInit takes io.Reader and wraps
// internally — *bufio.Reader satisfies both.
func newReader(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}
