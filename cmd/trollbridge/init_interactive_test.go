package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
// guard that confirms operator-supplied CA paths replace the
// canonical defaults verbatim. The default itself is now absolute
// (DefaultCACertPath, issue #14), so there is no relative path to
// regress to — the absence-assertion below is kept for defense-in-
// depth in case the template is ever rewritten with a relative
// default.
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
	// And the canonical default must not survive after the operator
	// supplied a custom path.
	if strings.Contains(out, "    cert_path: "+DefaultCACertPath) {
		t.Errorf("canonical default cert_path should have been replaced by the operator-supplied path")
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
		"user",         // install mode
		"local",        // topology
		"default-deny", // policy posture
		"n",            // interception
		"n",            // advisor
		"",
	}, "\n") + "\n")
	var out bytes.Buffer
	ans, err := runInteractiveInit(in, &out)
	if err != nil {
		t.Fatalf("runInteractiveInit: %v\n%s", err, out.String())
	}
	if ans.installMode != "user" || ans.topology != "local" || ans.mode != "default-deny" || ans.interception || ans.llmEnabled {
		t.Errorf("answers mis-collected: %+v", ans)
	}
}

func TestRunInteractiveInit_AOAIPromptsForEndpoint(t *testing.T) {
	// Force runAzFlow's azAvailable() to return false so the
	// manual-prompt path the test scripts is byte-identical to
	// pre-#132 behavior. Without this stub, a test environment
	// with `az` in PATH would surface the find/create offer and
	// the scripted input would be consumed as the action choice.
	defer overrideAzUnavailable()()
	endpoint := "https://contoso.openai.azure.com/openai/deployments/gpt4/chat/completions?api-version=2024-02-15-preview"
	in := newReader(strings.Join([]string{
		"user",
		"local",
		"default-ask",
		"n", // interception
		"y", // advisor
		"aoai",
		"gpt-4o",
		endpoint,
		"sk-azure-test", // LLM key (user-mode prompts for it)
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
	if ans.llmKey != "sk-azure-test" {
		t.Errorf("user-mode AOAI flow should collect the API key inline; got %q", ans.llmKey)
	}
}

// TestRunInteractiveInit_AOAIDefaultsModelToGPT4oMini closes #131:
// the wizard's model-prompt default was a Claude model name even
// after the operator picked aoai. With the provider-aware default,
// accepting the prompt's default yields gpt-4o-mini and the prompt's
// "[default]" text reflects it.
func TestRunInteractiveInit_AOAIDefaultsModelToGPT4oMini(t *testing.T) {
	defer overrideAzUnavailable()()
	endpoint := "https://contoso.openai.azure.com/openai/deployments/gpt4omini/chat/completions?api-version=2024-02-15-preview"
	in := newReader(strings.Join([]string{
		"user",
		"local",
		"default-ask",
		"n", // interception
		"y", // advisor
		"aoai",
		"",  // model: accept default
		endpoint,
		"sk-azure-test", // user-mode prompts for key
	}, "\n") + "\n")
	var out bytes.Buffer
	ans, err := runInteractiveInit(in, &out)
	if err != nil {
		t.Fatalf("runInteractiveInit: %v\n%s", err, out.String())
	}
	if ans.llmModel != "gpt-4o-mini" {
		t.Errorf("aoai accepting default model: llmModel = %q, want %q", ans.llmModel, "gpt-4o-mini")
	}
	// The prompt transcript must surface the new default so the
	// operator can see what they're accepting.
	if !strings.Contains(out.String(), "model [gpt-4o-mini]:") {
		t.Errorf("aoai model prompt should show [gpt-4o-mini] default; transcript:\n%s", out.String())
	}
	// Sanity: the rendered config from applyAnswers carries the model.
	rendered := applyAnswers(defaultConfigYAML, ans)
	if !strings.Contains(rendered, "model:    gpt-4o-mini") {
		t.Errorf("rendered config should contain `model: gpt-4o-mini`; got:\n%s", rendered)
	}
}

func TestRunInteractiveInit_AnthropicSkipsEndpointPrompt(t *testing.T) {
	in := newReader(strings.Join([]string{
		"user",
		"local",
		"default-ask",
		"n", // interception
		"y", // advisor
		"anthropic",
		"claude-opus-4-7",
		"sk-anthropic-test", // LLM key
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
	got := promptChoice(newReader("garbage\nlocal\n"), &buf, "topology",
		[]string{"local", "local-vm", "remote"}, "local")
	if got != "local" {
		t.Errorf("retry after rejected name should yield 'local'; got %q", got)
	}
	if !strings.Contains(buf.String(), "unknown choice") {
		t.Errorf("invalid choice should produce 'unknown choice' notice; got:\n%s", buf.String())
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

// TestInit_InteractiveInterception_DoesNotBootstrapCA closes
// issue #19: `trollbridge init` must NOT generate the CA inline.
// The operator running `init` may not be on the proxy host, may not
// own /etc/trollbridge/, and may not need the CA on this machine
// at all. CA generation is a separate `trollbridge ca init` step
// the operator runs on the proxy host.
//
// The test's load-bearing assertions are: (a) the YAML still
// reflects interception=on, (b) NO files appear at the canonical
// /etc/ paths during init (we cannot write there in CI anyway,
// which is the point), and (c) the next-steps output names the
// proxy host and the deferred `sudo trollbridge ca init` step.
func TestInit_InteractiveInterception_DoesNotBootstrapCA(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("daemon-mode transcript is sudo/unix-shaped (see printDaemonNextSteps); Windows daemon flow is not yet implemented (#107)")
	}
	dir := t.TempDir()

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
			"daemon", // install mode (exercises the never-bootstrap-inline rule)
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
	// Should NOT fail, even though the test runs as a non-root user
	// and /etc/trollbridge is not writable. `init` writes the yaml
	// only; CA generation defers to `trollbridge ca init`.
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init interactive should not require root; got err: %v\n%s", err, out.String())
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

	// The daemon-mode next-steps must name the deferred ca init step
	// (run as the trollbridge user, NOT as root).
	for _, want := range []string{
		"daemon-mode",
		"sudo -u trollbridge trollbridge ca init",
		"runs as the `trollbridge` system user (not root)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("next-steps missing %q in:\n%s", want, out.String())
		}
	}
	// Defense-in-depth: the output must not contain old "generated CA:"
	// lines that imply init created cert files locally.
	if strings.Contains(out.String(), "generated CA:") {
		t.Errorf("init must not report 'generated CA:' — CA generation is now a separate step (issue #19); got:\n%s", out.String())
	}
}

// TestInit_NextSteps_RemoteTopology_NamesCertDistribution covers
// the topology-awareness half: when the operator chose remote
// topology, next-steps include cert-transfer (scp) and per-consumer
// install steps. Tested under daemon-mode (the more common shape
// for remote topology).
func TestInit_NextSteps_RemoteTopology_NamesCertDistribution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("daemon-mode transcript is sudo/unix-shaped (see printDaemonNextSteps); Windows daemon flow is not yet implemented (#107)")
	}
	dir := t.TempDir()

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
			"daemon", // install mode
			"remote",
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
		t.Fatalf("init: %v\n%s", err, out.String())
	}

	for _, want := range []string{
		"scp",
		"trollbridge-ca.crt",
		"sudo trollbridge ca install --apply",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("remote-topology next-steps missing %q in:\n%s", want, out.String())
		}
	}
}

// TestInit_DaemonMode_LLM_DoesNotWriteKey: in daemon-mode the
// interactive LLM prompt does NOT collect the API key, and `init`
// does NOT write a key file — the operator writes it on the proxy
// host via `sudo -u trollbridge`. Yaml records the canonical
// /etc/trollbridge/llm.key path.
func TestInit_DaemonMode_LLM_DoesNotWriteKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("daemon-mode transcript is sudo/unix-shaped (see printDaemonNextSteps); Windows daemon flow is not yet implemented")
	}
	dir := t.TempDir()

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
			"daemon",
			"local",
			"default-ask",
			"n", // interception=off
			"y", // advisor=on
			"anthropic",
			"claude-opus-4-7",
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

	if _, err := os.Stat(filepath.Join(dir, "llm.key")); err == nil {
		t.Errorf("daemon-mode init must not write llm.key into the init dir")
	}

	body, err := os.ReadFile(filepath.Join(dir, "trollbridge.yaml"))
	if err != nil {
		t.Fatalf("read yaml: %v", err)
	}
	if !strings.Contains(string(body), "api_key_path: "+DefaultDaemonLLMKeyPath) {
		t.Errorf("daemon-mode YAML should record %s; got:\n%s", DefaultDaemonLLMKeyPath, body)
	}
	if !strings.Contains(string(body), "  enabled: true\n  provider: anthropic") {
		t.Errorf("YAML should reflect llm.enabled=true; got:\n%s", body)
	}
	for _, want := range []string{
		DefaultDaemonLLMKeyPath,
		"sudo -u trollbridge",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("daemon-mode transcript missing %q; got:\n%s", want, out.String())
		}
	}
}

// TestInit_UserMode_LLM_WritesKeyInline: in user-mode the operator
// types the API key at the prompt; init writes it to <init-dir>/
// llm.key with mode 0600. Yaml records the absolute path.
func TestInit_UserMode_LLM_WritesKeyInline(t *testing.T) {
	dir := t.TempDir()
	keyValue := "sk-user-mode-test"

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
			"user",
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
		t.Fatalf("init: %v\n%s", err, out.String())
	}

	wantKeyPath, err := filepath.Abs(filepath.Join(dir, "llm.key"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(wantKeyPath)
	if err != nil {
		t.Fatalf("user-mode init should write llm.key at %s: %v", wantKeyPath, err)
	}
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("llm.key mode = %o, want 0600", mode)
		}
	}
	got, err := os.ReadFile(wantKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != keyValue {
		t.Errorf("llm.key contents = %q, want %q", string(got), keyValue)
	}

	body, err := os.ReadFile(filepath.Join(dir, "trollbridge.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "api_key_path: "+wantKeyPath) {
		t.Errorf("YAML should record absolute api_key_path %q; got:\n%s", wantKeyPath, body)
	}
}

func TestInit_InteractiveAOAIWritesEndpointInYaml(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("daemon-mode transcript is sudo/unix-shaped; Windows daemon flow is not yet implemented")
	}
	dir := t.TempDir()
	endpoint := "https://contoso.openai.azure.com/openai/deployments/gpt4/chat/completions?api-version=2024-02-15-preview"

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
			"daemon", // install mode (test exercises daemon-mode AOAI flow)
			"local",
			"default-ask",
			"n", // interception=off
			"y", // advisor=on
			"aoai",
			"gpt-4o",
			endpoint,
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
	// Per #21: yaml records the canonical daemon-mode llm.key path;
	// init does not write the key file (operator handles that on the
	// proxy host as root).
	if !strings.Contains(string(body), "api_key_path: "+DefaultDaemonLLMKeyPath) {
		t.Errorf("AOAI flow should record canonical %s path; got:\n%s", DefaultDaemonLLMKeyPath, body)
	}
	if _, err := os.Stat(filepath.Join(dir, "llm.key")); err == nil {
		t.Errorf("init must not write llm.key into the init dir (issue #21)")
	}
}

// newReader returns a *bufio.Reader over s. The prompt helpers
// take *bufio.Reader; runInteractiveInit takes io.Reader and wraps
// internally — *bufio.Reader satisfies both.
func newReader(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}
