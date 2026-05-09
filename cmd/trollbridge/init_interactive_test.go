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

func TestApplyAnswers_LocalDefaults(t *testing.T) {
	out := applyAnswers(defaultConfigYAML, initAnswers{
		topology: "local",
		mode:     "default-ask",
	})
	if out != defaultConfigYAML {
		t.Errorf("local + default-ask + no overrides should produce the static template byte-for-byte")
	}
}

func TestApplyAnswers_LocalVMTopologyAllBind(t *testing.T) {
	out := applyAnswers(defaultConfigYAML, initAnswers{
		topology: "local-vm",
		mode:     "default-ask",
	})
	if !strings.Contains(out, "proxy:   all:8080") {
		t.Errorf("local-vm topology should bind on all:8080; got:\n%s", out)
	}
	if strings.Contains(out, "proxy:   lo:8080") {
		t.Errorf("local-vm topology must replace the lo:8080 default; got it still present")
	}
}

func TestApplyAnswers_RemoteTopologyAllBind(t *testing.T) {
	out := applyAnswers(defaultConfigYAML, initAnswers{
		topology: "remote",
		mode:     "default-deny",
	})
	if !strings.Contains(out, "proxy:   all:8080") {
		t.Errorf("remote topology should bind on all:8080; got:\n%s", out)
	}
	if !strings.Contains(out, "mode: default-deny") {
		t.Errorf("mode substitution missing; got:\n%s", out)
	}
}

func TestApplyAnswers_InterceptionEnabled(t *testing.T) {
	out := applyAnswers(defaultConfigYAML, initAnswers{
		topology:     "local",
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

// TestApplyAnswers_InterceptionAbsoluteCAPaths is the regression
// guard for the follow-on bug surfaced by issue #8: when init
// writes the CA outside cwd (because the dir default now points at
// $HOME/.config/trollbridge/), the YAML's interception.ca paths
// must be absolute, not relative to cwd. Otherwise the running
// daemon (started from a different cwd) would not find the CA.
func TestApplyAnswers_InterceptionAbsoluteCAPaths(t *testing.T) {
	out := applyAnswers(defaultConfigYAML, initAnswers{
		topology:     "local",
		mode:         "default-ask",
		interception: true,
		caCertPath:   "/var/lib/trollbridge/ca.crt",
		caKeyPath:    "/var/lib/trollbridge/ca.key",
	})
	if !strings.Contains(out, "    cert_path: /var/lib/trollbridge/ca.crt") {
		t.Errorf("absolute cert_path substitution missing; got:\n%s", out)
	}
	if !strings.Contains(out, "    key_path:  /var/lib/trollbridge/ca.key") {
		t.Errorf("absolute key_path substitution missing; got:\n%s", out)
	}
	if strings.Contains(out, "    cert_path: ./trollbridge-ca.crt") {
		t.Errorf("relative cert_path default should have been replaced")
	}
}

func TestApplyAnswers_LLMEnabledWithProvider(t *testing.T) {
	out := applyAnswers(defaultConfigYAML, initAnswers{
		topology:    "local",
		mode:        "default-ask",
		llmEnabled:  true,
		llmProvider: "aoai",
		llmModel:    "gpt-4o",
		llmEndpoint: "https://example.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-02-15-preview",
		llmKeyPath:  "/var/secrets/aoai.key",
	})
	for _, want := range []string{
		"  enabled: true\n  provider: aoai",
		"  model:    gpt-4o",
		"  api_key_path: /var/secrets/aoai.key",
		"  endpoint: https://example.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-02-15-preview",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("LLM substitution missing %q in output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "  endpoint: https://api.anthropic.com") {
		t.Errorf("aoai endpoint substitution should have replaced the anthropic default; got:\n%s", out)
	}
}

func TestApplyAnswers_LLMEnabledAnthropicKeepsDefaultEndpoint(t *testing.T) {
	out := applyAnswers(defaultConfigYAML, initAnswers{
		topology:    "local",
		mode:        "default-ask",
		llmEnabled:  true,
		llmProvider: "anthropic",
		llmModel:    "claude-opus-4-7",
		llmKeyPath:  "/home/op/.config/trollbridge/llm.key",
	})
	if !strings.Contains(out, "  endpoint: https://api.anthropic.com") {
		t.Errorf("anthropic provider should preserve the default endpoint; got:\n%s", out)
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
	// Non-TTY path: in is a strings.Reader (not *os.File), so the TTY
	// branch is skipped and bufio drives the read. Echo is moot.
	in1 := strings.NewReader("\n\n")
	r1 := newReader("\n\n")
	_, err := promptSecret(in1, r1, &buf, "key")
	if err == nil {
		t.Error("two empty inputs should produce an error")
	}
	in2 := strings.NewReader("\nsk-test\n")
	r2 := newReader("\nsk-test\n")
	got, err := promptSecret(in2, r2, &buf, "key")
	if err != nil {
		t.Fatalf("non-empty after retry should succeed: %v", err)
	}
	if got != "sk-test" {
		t.Errorf("got %q, want sk-test", got)
	}
}

func TestPromptSecret_UsesReadPasswordOnTTY(t *testing.T) {
	prevTerm := isTerminal
	prevReadPw := readPassword
	isTerminal = func(int) bool { return true }
	calledFd := -1
	readPassword = func(fd int) ([]byte, error) {
		calledFd = fd
		return []byte("sk-tty-secret"), nil
	}
	t.Cleanup(func() {
		isTerminal = prevTerm
		readPassword = prevReadPw
	})

	// We need an *os.File so the type assertion succeeds; a pipe
	// gives us that without needing a real terminal.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = pr.Close() })
	_ = pw.Close()

	var buf bytes.Buffer
	got, err := promptSecret(pr, bufio.NewReader(pr), &buf, "key")
	if err != nil {
		t.Fatalf("promptSecret: %v", err)
	}
	if got != "sk-tty-secret" {
		t.Errorf("got %q, want sk-tty-secret", got)
	}
	if calledFd != int(pr.Fd()) {
		t.Errorf("readPassword called with fd %d, want %d (pipe-read fd)", calledFd, pr.Fd())
	}
}

func TestPromptSecret_FallsBackToBufioWhenNonTTY(t *testing.T) {
	prevTerm := isTerminal
	prevReadPw := readPassword
	isTerminal = func(int) bool { return false }
	called := false
	readPassword = func(int) ([]byte, error) {
		called = true
		return nil, nil
	}
	t.Cleanup(func() {
		isTerminal = prevTerm
		readPassword = prevReadPw
	})

	in := strings.NewReader("scripted-key\n")
	var buf bytes.Buffer
	got, err := promptSecret(in, newReader("scripted-key\n"), &buf, "key")
	if err != nil {
		t.Fatalf("promptSecret: %v", err)
	}
	if got != "scripted-key" {
		t.Errorf("got %q, want scripted-key", got)
	}
	if called {
		t.Errorf("readPassword must NOT be called when isTerminal is false")
	}
}

func TestRunInteractiveInit_HappyPathAllOff(t *testing.T) {
	in := newReader(strings.Join([]string{
		"local",        // topology
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
	if ans.topology != "local" || ans.mode != "default-deny" || ans.interception || ans.llmEnabled {
		t.Errorf("answers mis-collected: %+v", ans)
	}
}

func TestRunInteractiveInit_AOAIPromptsForEndpoint(t *testing.T) {
	endpoint := "https://contoso.openai.azure.com/openai/deployments/gpt4/chat/completions?api-version=2024-02-15-preview"
	in := newReader(strings.Join([]string{
		"local",
		"default-ask",
		"n", // interception
		"y", // advisor
		"aoai",
		"gpt-4o",
		endpoint,
		"sk-azure-test",
	}, "\n") + "\n")
	var out bytes.Buffer
	ans, err := runInteractiveInit(in, &out)
	if err != nil {
		t.Fatalf("runInteractiveInit: %v\n%s", err, out.String())
	}
	if ans.llmEndpoint != endpoint {
		t.Errorf("llmEndpoint = %q, want %q", ans.llmEndpoint, endpoint)
	}
	if !strings.Contains(out.String(), "endpoint URL") {
		t.Errorf("AOAI flow should prompt for endpoint URL; transcript:\n%s", out.String())
	}
}

func TestRunInteractiveInit_AnthropicSkipsEndpointPrompt(t *testing.T) {
	in := newReader(strings.Join([]string{
		"local",
		"default-ask",
		"n", // interception
		"y", // advisor
		"anthropic",
		"claude-opus-4-7",
		"sk-anthropic-test",
	}, "\n") + "\n")
	var out bytes.Buffer
	ans, err := runInteractiveInit(in, &out)
	if err != nil {
		t.Fatalf("runInteractiveInit: %v\n%s", err, out.String())
	}
	if ans.llmEndpoint != "" {
		t.Errorf("anthropic provider must not collect an endpoint; got %q", ans.llmEndpoint)
	}
	if strings.Contains(out.String(), "endpoint URL") {
		t.Errorf("anthropic flow should NOT prompt for endpoint URL; transcript:\n%s", out.String())
	}
}

func TestPromptRequiredString_RejectsEmptyThenAccepts(t *testing.T) {
	var buf bytes.Buffer
	_, err := promptRequiredString(newReader("\n\n"), &buf, "x")
	if err == nil {
		t.Error("two empty inputs should produce an error")
	}
	got, err := promptRequiredString(newReader("\nvalue\n"), &buf, "x")
	if err != nil {
		t.Fatalf("non-empty after retry should succeed: %v", err)
	}
	if got != "value" {
		t.Errorf("got %q, want %q", got, "value")
	}
}

func TestPromptChoice_RejectsOldPresetName(t *testing.T) {
	var buf bytes.Buffer
	got := promptChoice(newReader("laptop\nlocal\n"), &buf, "topology",
		[]string{"local", "local-vm", "remote"}, "local")
	if got != "local" {
		t.Errorf("retry after rejected old name should yield 'local'; got %q", got)
	}
	if !strings.Contains(buf.String(), "unknown choice") {
		t.Errorf("old preset name should produce 'unknown choice' notice; got:\n%s", buf.String())
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
			"local",
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

func TestInit_InteractiveLLMKeyAlongsideYaml(t *testing.T) {
	dir := t.TempDir()
	keyValue := "sk-test-12345"
	wantKeyPath, err := filepath.Abs(filepath.Join(dir, "llm.key"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}

	prev := isTerminal
	isTerminal = func(int) bool { return true }
	prevPw := readPassword
	readPassword = func(int) ([]byte, error) { return []byte(keyValue), nil }
	t.Cleanup(func() {
		isTerminal = prev
		readPassword = prevPw
	})

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = pr.Close() })
	go func() {
		defer pw.Close()
		_, _ = pw.WriteString(strings.Join([]string{
			"local",
			"default-ask",
			"n", // interception=off
			"y", // advisor=on
			"anthropic",
			"claude-opus-4-7",
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

	info, err := os.Stat(wantKeyPath)
	if err != nil {
		t.Fatalf("LLM key file not written at %s: %v", wantKeyPath, err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("LLM key mode = %o, want 0600", mode)
	}
	got, err := os.ReadFile(wantKeyPath)
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
	if !strings.Contains(string(body), "api_key_path: "+wantKeyPath) {
		t.Errorf("YAML should reference <dir>/llm.key (%s); got:\n%s", wantKeyPath, body)
	}
	if !strings.Contains(string(body), "  enabled: true\n  provider: anthropic") {
		t.Errorf("YAML should reflect llm.enabled=true; got:\n%s", body)
	}
	// The flow must not have asked for a path: the transcript's
	// prompt labels should not mention "API key path".
	if strings.Contains(out.String(), "API key path") {
		t.Errorf("init should not prompt for the API key path anymore; transcript:\n%s", out.String())
	}
}

func TestInit_InteractiveAOAIWritesEndpointInYaml(t *testing.T) {
	dir := t.TempDir()
	keyValue := "sk-azure-test"
	endpoint := "https://contoso.openai.azure.com/openai/deployments/gpt4/chat/completions?api-version=2024-02-15-preview"

	prev := isTerminal
	isTerminal = func(int) bool { return true }
	prevPw := readPassword
	readPassword = func(int) ([]byte, error) { return []byte(keyValue), nil }
	t.Cleanup(func() {
		isTerminal = prev
		readPassword = prevPw
	})

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = pr.Close() })
	go func() {
		defer pw.Close()
		_, _ = pw.WriteString(strings.Join([]string{
			"local",
			"default-ask",
			"n", // interception=off
			"y", // advisor=on
			"aoai",
			"gpt-4o",
			endpoint,
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
		t.Fatalf("init interactive aoai: %v\n%s", err, out.String())
	}

	body, err := os.ReadFile(filepath.Join(dir, "trollbridge.yaml"))
	if err != nil {
		t.Fatalf("read yaml: %v", err)
	}
	if !strings.Contains(string(body), "  endpoint: "+endpoint) {
		t.Errorf("YAML should carry the operator-supplied endpoint; got:\n%s", body)
	}
	if strings.Contains(string(body), "  endpoint: https://api.anthropic.com") {
		t.Errorf("anthropic default endpoint should have been replaced for aoai")
	}
	if !strings.Contains(string(body), "  enabled: true\n  provider: aoai") {
		t.Errorf("YAML should reflect provider=aoai; got:\n%s", body)
	}
	wantKeyPath, err := filepath.Abs(filepath.Join(dir, "llm.key"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if !strings.Contains(string(body), "api_key_path: "+wantKeyPath) {
		t.Errorf("AOAI flow should still place the key at <dir>/llm.key; got:\n%s", body)
	}
	if _, err := os.Stat(wantKeyPath); err != nil {
		t.Errorf("AOAI key file not written at %s: %v", wantKeyPath, err)
	}
}

// newReader returns a *bufio.Reader over s. The prompt helpers
// take *bufio.Reader; runInteractiveInit takes io.Reader and wraps
// internally — *bufio.Reader satisfies both.
func newReader(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}
