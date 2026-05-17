package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// init_az_test.go pins the az-CLI orchestration for `trollbridge
// init`'s AOAI provider branch (closes #132). All tests mock the
// `azExec` package var so they run without `az` installed; the
// real-az verification happens on the operator's machine.

// overrideAzUnavailable installs an azExec stub that forces
// azAvailable() to return false (so runAzFlow silently skips).
// Used by the existing AOAI prompt-flow tests in
// init_interactive_test.go to keep their scripted input
// byte-identical to pre-#132 expectations regardless of whether
// the test environment happens to have az installed.
func overrideAzUnavailable() func() {
	prev := azExec
	azExec = func(args ...string) ([]byte, error) {
		return nil, errors.New("az not available (test stub)")
	}
	return func() { azExec = prev }
}

// stubAz replaces azExec with a canned-response table. The keys are
// the joined args passed to azExec; the values are either a JSON
// blob to return or an error to surface.
type stubAz struct {
	t        *testing.T
	canned   map[string]string // joinedArgs -> stdout
	errs     map[string]error  // joinedArgs -> error (takes precedence)
	calls    []string          // recording for assertions
}

func newStubAz(t *testing.T) *stubAz {
	return &stubAz{t: t, canned: map[string]string{}, errs: map[string]error{}}
}

func (s *stubAz) exec(args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	s.calls = append(s.calls, joined)
	if err, ok := s.errs[joined]; ok {
		return nil, err
	}
	if body, ok := s.canned[joined]; ok {
		return []byte(body), nil
	}
	return nil, fmt.Errorf("stubAz: no canned response for %q", joined)
}

// install swaps azExec for the lifetime of the test.
func (s *stubAz) install() func() {
	prev := azExec
	azExec = s.exec
	return func() { azExec = prev }
}

// TestAzAvailable_BothChecksPass: --version + account show succeed.
func TestAzAvailable_BothChecksPass(t *testing.T) {
	s := newStubAz(t)
	s.canned["--version"] = ""
	s.canned["account show -o json"] = `{"id":"sub-1"}`
	defer s.install()()
	if !azAvailable() {
		t.Errorf("azAvailable: false when both probes succeed")
	}
}

// TestAzAvailable_VersionFails: az not in PATH (subprocess error).
func TestAzAvailable_VersionFails(t *testing.T) {
	s := newStubAz(t)
	s.errs["--version"] = errors.New("exec: az: not found")
	defer s.install()()
	if azAvailable() {
		t.Errorf("azAvailable: true when az --version fails")
	}
}

// TestAzAvailable_NotLoggedIn: az present but no active subscription.
func TestAzAvailable_NotLoggedIn(t *testing.T) {
	s := newStubAz(t)
	s.canned["--version"] = ""
	s.errs["account show -o json"] = errors.New("Please run 'az login'")
	defer s.install()()
	if azAvailable() {
		t.Errorf("azAvailable: true when account show fails")
	}
}

// TestListAOAIAccounts_FiltersByKind confirms we filter the full
// Cognitive Services account list down to kind==OpenAI.
func TestListAOAIAccounts_FiltersByKind(t *testing.T) {
	s := newStubAz(t)
	s.canned["cognitiveservices account list -o json"] = `[
	  {"name":"speech-1","resourceGroup":"rg-a","kind":"SpeechServices","location":"eastus","properties":{"endpoint":"https://x"}},
	  {"name":"openai-east","resourceGroup":"rg-b","kind":"OpenAI","location":"eastus","properties":{"endpoint":"https://openai-east.openai.azure.com/"}},
	  {"name":"openai-west","resourceGroup":"rg-c","kind":"OpenAI","location":"westus2","properties":{"endpoint":"https://openai-west.openai.azure.com/"}}
	]`
	defer s.install()()

	accounts, err := listAOAIAccounts()
	if err != nil {
		t.Fatalf("listAOAIAccounts: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("listAOAIAccounts: got %d accounts, want 2 (only OpenAI kind)", len(accounts))
	}
	if accounts[0].Name != "openai-east" || accounts[1].Name != "openai-west" {
		t.Errorf("listAOAIAccounts: unexpected names %v", accounts)
	}
}

// TestAOAIEndpointURL_StripsTrailingSlash confirms the endpoint URL
// composition handles azure's optional trailing-slash on the
// account endpoint cleanly.
func TestAOAIEndpointURL_StripsTrailingSlash(t *testing.T) {
	got := aoaiEndpointURL("https://openai-east.openai.azure.com/", "gpt-4o-mini")
	want := "https://openai-east.openai.azure.com/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-02-15-preview"
	if got != want {
		t.Errorf("aoaiEndpointURL trailing slash: got %q want %q", got, want)
	}
	got = aoaiEndpointURL("https://openai-east.openai.azure.com", "gpt-4o")
	want = "https://openai-east.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-02-15-preview"
	if got != want {
		t.Errorf("aoaiEndpointURL no slash: got %q want %q", got, want)
	}
}

// TestRunAzFlow_SkipsWhenAzUnavailable confirms the orchestrator
// leaves ans untouched and returns silently when az is not in PATH
// — preserving the manual flow byte-identical to today.
func TestRunAzFlow_SkipsWhenAzUnavailable(t *testing.T) {
	s := newStubAz(t)
	s.errs["--version"] = errors.New("not found")
	defer s.install()()

	in := newReader("")
	var out bytes.Buffer
	ans := initAnswers{installMode: "user"}
	runAzFlow(in, &out, &ans)
	if ans.llmEndpoint != "" || ans.llmKey != "" {
		t.Errorf("runAzFlow with no az should not modify ans; got %+v", ans)
	}
	if out.Len() != 0 {
		t.Errorf("runAzFlow with no az should produce no output; got %q", out.String())
	}
}

// TestRunAzFlow_HintWhenNotLoggedIn confirms that when `az` is in
// PATH but `az account show` fails, the orchestrator prints the
// activation hint (closes #136) and then falls through silently —
// without modifying ans — so the existing manual prompts continue
// to drive the wizard.
func TestRunAzFlow_HintWhenNotLoggedIn(t *testing.T) {
	s := newStubAz(t)
	s.canned["--version"] = "azure-cli 2.x"
	s.errs["account show -o json"] = errors.New("Please run 'az login' to setup account.")
	defer s.install()()

	in := newReader("")
	var out bytes.Buffer
	ans := initAnswers{installMode: "user"}
	runAzFlow(in, &out, &ans)

	if ans.llmEndpoint != "" || ans.llmKey != "" || ans.llmModel != "" {
		t.Errorf("runAzFlow not-logged-in should not modify ans; got %+v", ans)
	}
	got := out.String()
	for _, want := range []string{"az detected but not authenticated", "az login", "trollbridge init"} {
		if !strings.Contains(got, want) {
			t.Errorf("runAzFlow not-logged-in transcript missing %q; full output:\n%s", want, got)
		}
	}
}

// TestRunAzFlow_SkipChoiceLeavesAnsUntouched: az is available, but
// the operator picks `skip` at the action prompt.
func TestRunAzFlow_SkipChoiceLeavesAnsUntouched(t *testing.T) {
	s := newStubAz(t)
	s.canned["--version"] = ""
	s.canned["account show -o json"] = `{"id":"sub-1"}`
	defer s.install()()

	in := newReader("skip\n")
	var out bytes.Buffer
	ans := initAnswers{installMode: "user"}
	runAzFlow(in, &out, &ans)
	if ans.llmEndpoint != "" || ans.llmKey != "" {
		t.Errorf("runAzFlow with operator skip should not modify ans; got %+v", ans)
	}
}

// TestRunAzFlow_FindHappyPath: az available, operator picks find,
// one account with one deployment; ans populated.
func TestRunAzFlow_FindHappyPath(t *testing.T) {
	s := newStubAz(t)
	s.canned["--version"] = ""
	s.canned["account show -o json"] = `{"id":"sub-1"}`
	s.canned["cognitiveservices account list -o json"] = `[
	  {"name":"openai-east","resourceGroup":"rg-b","kind":"OpenAI","location":"eastus","properties":{"endpoint":"https://openai-east.openai.azure.com/"}}
	]`
	s.canned["cognitiveservices account deployment list -n openai-east -g rg-b -o json"] = `[
	  {"name":"gpt-4o-mini-dep","properties":{"model":{"name":"gpt-4o-mini","version":"2024-07-18"}}}
	]`
	s.canned["cognitiveservices account keys list -n openai-east -g rg-b -o json"] = `{"key1":"SECRET-K1","key2":"SECRET-K2"}`
	defer s.install()()

	// Scripted operator: pick find, then accept defaults (1 for
	// account, 1 for deployment).
	in := newReader(strings.Join([]string{"find", "1", "1"}, "\n") + "\n")
	var out bytes.Buffer
	ans := initAnswers{installMode: "user", llmProvider: "aoai", llmModel: "gpt-4o-mini"}
	runAzFlow(in, &out, &ans)

	wantEndpoint := "https://openai-east.openai.azure.com/openai/deployments/gpt-4o-mini-dep/chat/completions?api-version=2024-02-15-preview"
	if ans.llmEndpoint != wantEndpoint {
		t.Errorf("ans.llmEndpoint = %q, want %q", ans.llmEndpoint, wantEndpoint)
	}
	if ans.llmModel != "gpt-4o-mini" {
		t.Errorf("ans.llmModel = %q, want %q", ans.llmModel, "gpt-4o-mini")
	}
	if ans.llmKey != "SECRET-K1" {
		t.Errorf("ans.llmKey = %q, want %q (key1)", ans.llmKey, "SECRET-K1")
	}
}

// TestRunAzFlow_FindHappyPath_DaemonModeSkipsKey confirms the
// daemon-mode key-handling rule: the key is NOT fetched in daemon
// mode (operator installs it separately on the proxy host).
func TestRunAzFlow_FindHappyPath_DaemonModeSkipsKey(t *testing.T) {
	s := newStubAz(t)
	s.canned["--version"] = ""
	s.canned["account show -o json"] = `{"id":"sub-1"}`
	s.canned["cognitiveservices account list -o json"] = `[
	  {"name":"openai-east","resourceGroup":"rg-b","kind":"OpenAI","location":"eastus","properties":{"endpoint":"https://openai-east.openai.azure.com/"}}
	]`
	s.canned["cognitiveservices account deployment list -n openai-east -g rg-b -o json"] = `[
	  {"name":"gpt-4o-mini-dep","properties":{"model":{"name":"gpt-4o-mini","version":"2024-07-18"}}}
	]`
	defer s.install()()

	in := newReader("find\n1\n1\n")
	var out bytes.Buffer
	ans := initAnswers{installMode: "daemon", llmProvider: "aoai", llmModel: "gpt-4o-mini"}
	runAzFlow(in, &out, &ans)

	if ans.llmEndpoint == "" {
		t.Error("ans.llmEndpoint not populated in daemon-mode find flow")
	}
	if ans.llmKey != "" {
		t.Errorf("daemon-mode: ans.llmKey should NOT be populated by az; got %q", ans.llmKey)
	}
	// Daemon-mode hint surfaces in the transcript so the operator
	// knows the next step.
	if !strings.Contains(out.String(), "daemon-mode") {
		t.Errorf("daemon-mode flow should mention the daemon-mode key-install hint; transcript:\n%s", out.String())
	}
	// Recorded calls: no `keys list` should have run.
	for _, c := range s.calls {
		if strings.HasPrefix(c, "cognitiveservices account keys list") {
			t.Errorf("daemon-mode: az keys list should NOT have been called; got %q", c)
		}
	}
}

// TestRunAzFlow_FindWithNoAccountsSurfacesAndLoops: when the
// operator picks `find` but the subscription has no OpenAI
// accounts, the orchestrator surfaces the message and returns to
// the action prompt; operator can then pick `skip`.
func TestRunAzFlow_FindWithNoAccountsSurfacesAndLoops(t *testing.T) {
	s := newStubAz(t)
	s.canned["--version"] = ""
	s.canned["account show -o json"] = `{"id":"sub-1"}`
	s.canned["cognitiveservices account list -o json"] = `[]`
	defer s.install()()

	in := newReader("find\nskip\n")
	var out bytes.Buffer
	ans := initAnswers{installMode: "user", llmProvider: "aoai"}
	runAzFlow(in, &out, &ans)
	if !strings.Contains(out.String(), "no OpenAI accounts found") {
		t.Errorf("expected hint about no OpenAI accounts; transcript:\n%s", out.String())
	}
	if ans.llmEndpoint != "" {
		t.Errorf("ans.llmEndpoint should not be set; got %q", ans.llmEndpoint)
	}
}

// TestRunAzFlow_CreateHappyPath: operator picks create, types group
// + name + accepts deployment + model defaults; az calls succeed;
// ans populated.
func TestRunAzFlow_CreateHappyPath(t *testing.T) {
	s := newStubAz(t)
	s.canned["--version"] = ""
	s.canned["account show -o json"] = `{"id":"sub-1"}`
	s.canned["group list -o json"] = `[
	  {"name":"existing-rg","location":"eastus"}
	]`
	// New resource group typed by the operator → createResourceGroup fires.
	s.canned["group create -n newrg -l eastus -o json"] = `{}`
	s.canned["cognitiveservices account create -n mynewacct -g newrg --kind OpenAI --sku S0 -l eastus -o json"] =
		`{"name":"mynewacct","resourceGroup":"newrg","kind":"OpenAI","location":"eastus","properties":{"endpoint":"https://mynewacct.openai.azure.com/"}}`
	s.canned["cognitiveservices account deployment create -n mynewacct -g newrg --deployment-name gpt-4o-mini --model-name gpt-4o-mini --model-format OpenAI -o json"] =
		`{"name":"gpt-4o-mini","properties":{"model":{"name":"gpt-4o-mini","version":"2024-07-18"}}}`
	s.canned["cognitiveservices account keys list -n mynewacct -g newrg -o json"] = `{"key1":"CREATED-K1","key2":"K2"}`
	defer s.install()()

	// Script: create, type new group "newrg", accept eastus, type
	// account name "mynewacct", accept deployment default, accept
	// model default, blank model version.
	in := newReader(strings.Join([]string{
		"create",
		"newrg",     // resource group (new name)
		"eastus",    // location (default)
		"mynewacct", // account name
		"gpt-4o-mini", // deployment name (default; operator just hits return → default applies; explicit here so scripted reader stays unambiguous)
		"gpt-4o-mini", // model
		"",            // model version blank
	}, "\n") + "\n")
	var out bytes.Buffer
	ans := initAnswers{installMode: "user", llmProvider: "aoai", llmModel: "gpt-4o-mini"}
	runAzFlow(in, &out, &ans)
	if !strings.Contains(ans.llmEndpoint, "mynewacct.openai.azure.com") || !strings.Contains(ans.llmEndpoint, "gpt-4o-mini") {
		t.Errorf("create-flow endpoint missing account/deployment substring: %q", ans.llmEndpoint)
	}
	if ans.llmKey != "CREATED-K1" {
		t.Errorf("create-flow key = %q, want %q", ans.llmKey, "CREATED-K1")
	}
}

// TestRunAzFlow_FindErrorLoopsBackToAction: the first az call inside
// find fails; the orchestrator surfaces the error and re-prompts;
// operator can then skip.
func TestRunAzFlow_FindErrorLoopsBackToAction(t *testing.T) {
	s := newStubAz(t)
	s.canned["--version"] = ""
	s.canned["account show -o json"] = `{"id":"sub-1"}`
	s.errs["cognitiveservices account list -o json"] = errors.New("Forbidden: missing role")
	defer s.install()()

	in := newReader("find\nskip\n")
	var out bytes.Buffer
	ans := initAnswers{installMode: "user", llmProvider: "aoai"}
	runAzFlow(in, &out, &ans)
	if !strings.Contains(out.String(), "az error listing OpenAI accounts") {
		t.Errorf("expected az error message in transcript; got %q", out.String())
	}
	if ans.llmEndpoint != "" {
		t.Errorf("ans.llmEndpoint should not be set after az error; got %q", ans.llmEndpoint)
	}
}

