package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner records every step it is asked to run and optionally
// fails on a specific step index (0-based). It does not exec
// anything — the test replaces the live exec path so assertions
// run without root or filesystem mutation.
type fakeRunner struct {
	calls    []installStep
	failAt   int  // -1 = never fail
	failBoom bool // observed when failAt fired
}

func newFakeRunner() *fakeRunner { return &fakeRunner{failAt: -1} }

func (f *fakeRunner) run(step installStep, out io.Writer) error {
	idx := len(f.calls)
	f.calls = append(f.calls, step)
	fmt.Fprintf(out, "(fake) ran: %s\n", strings.Join(step.argv, " "))
	if f.failAt == idx {
		f.failBoom = true
		return errors.New("fake failure")
	}
	return nil
}

// writeTempCert writes a placeholder file for cert-existence
// checks. The contents do not matter — applyInstall only stat()s
// the path.
func writeTempCert(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(p, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return p
}

func privileged() bool   { return true }
func unprivileged() bool { return false }

func TestCAInstallApply_RefusesOnWindows(t *testing.T) {
	cert := writeTempCert(t)
	runner := newFakeRunner()
	var buf bytes.Buffer
	err := applyInstall(&buf, strings.NewReader(""), platformWindows, cert, false, runner, privileged)
	if err == nil {
		t.Fatal("expected refusal on Windows")
	}
	if !strings.Contains(err.Error(), "Windows") {
		t.Errorf("error should name Windows; got: %v", err)
	}
	if !strings.Contains(err.Error(), "elevated") {
		t.Errorf("error should hint at elevated shell; got: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("Windows refusal must not run any step; got %d calls", len(runner.calls))
	}
}

func TestCAInstallApply_RefusesOnLinuxUnknown(t *testing.T) {
	cert := writeTempCert(t)
	runner := newFakeRunner()
	var buf bytes.Buffer
	err := applyInstall(&buf, strings.NewReader(""), platformLinuxUnknown, cert, false, runner, privileged)
	if err == nil {
		t.Fatal("expected refusal on LinuxUnknown")
	}
	if !strings.Contains(err.Error(), "Linux") || !strings.Contains(err.Error(), "auto-detection") {
		t.Errorf("error should explain detection failure; got: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("LinuxUnknown refusal must not run any step; got %d calls", len(runner.calls))
	}
}

func TestCAInstallApply_RefusesOnUnknownOS(t *testing.T) {
	cert := writeTempCert(t)
	runner := newFakeRunner()
	var buf bytes.Buffer
	err := applyInstall(&buf, strings.NewReader(""), platformUnknown, cert, false, runner, privileged)
	if err == nil {
		t.Fatal("expected refusal on platformUnknown")
	}
	if len(runner.calls) != 0 {
		t.Errorf("Unknown-OS refusal must not run any step; got %d calls", len(runner.calls))
	}
}

func TestCAInstallApply_RefusesWhenNotRoot(t *testing.T) {
	cert := writeTempCert(t)
	runner := newFakeRunner()
	var buf bytes.Buffer
	err := applyInstall(&buf, strings.NewReader(""), platformLinuxDebian, cert, true, runner, unprivileged)
	if err == nil {
		t.Fatal("expected refusal when not root")
	}
	if !strings.Contains(err.Error(), "sudo") {
		t.Errorf("error should hint at sudo; got: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("not-root refusal must not run any step; got %d calls", len(runner.calls))
	}
}

func TestCAInstallApply_RefusesWhenCertMissing(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.crt")
	runner := newFakeRunner()
	var buf bytes.Buffer
	err := applyInstall(&buf, strings.NewReader(""), platformLinuxDebian, missing, true, runner, privileged)
	if err == nil {
		t.Fatal("expected refusal when cert missing")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error should name the missing cert path; got: %v", err)
	}
	if !strings.Contains(err.Error(), "ca init") {
		t.Errorf("error should point at `ca init`; got: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("missing-cert refusal must not run any step; got %d calls", len(runner.calls))
	}
}

func TestCAInstallApply_DeclinedPromptDoesNotRun(t *testing.T) {
	cert := writeTempCert(t)
	runner := newFakeRunner()
	var buf bytes.Buffer
	err := applyInstall(&buf, strings.NewReader("n\n"), platformLinuxDebian, cert, false, runner, privileged)
	if err == nil {
		t.Fatal("expected error when operator declines prompt")
	}
	if !strings.Contains(err.Error(), "aborted") {
		t.Errorf("error should report operator abort; got: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("declined-prompt path must not run any step; got %d calls: %+v", len(runner.calls), runner.calls)
	}
	out := buf.String()
	if !strings.Contains(out, "Proceed? [y/N]") {
		t.Errorf("output should have shown the confirmation prompt; got:\n%s", out)
	}
}

func TestCAInstallApply_EmptyInputDeclines(t *testing.T) {
	cert := writeTempCert(t)
	runner := newFakeRunner()
	var buf bytes.Buffer
	// Empty stdin (EOF on first read) must not be interpreted as yes.
	err := applyInstall(&buf, strings.NewReader(""), platformLinuxDebian, cert, false, runner, privileged)
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("EOF on prompt should be treated as decline; got: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("EOF-on-prompt path must not run any step; got %d calls", len(runner.calls))
	}
}

func TestCAInstallApply_AcceptedPromptRunsAllSteps(t *testing.T) {
	cert := writeTempCert(t)
	runner := newFakeRunner()
	var buf bytes.Buffer
	err := applyInstall(&buf, strings.NewReader("y\n"), platformLinuxDebian, cert, false, runner, privileged)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, buf.String())
	}
	want := installStepsFor(platformLinuxDebian, cert)
	if len(runner.calls) != len(want) {
		t.Fatalf("ran %d steps, want %d", len(runner.calls), len(want))
	}
	for i := range want {
		if !equalArgv(runner.calls[i].argv, want[i].argv) {
			t.Errorf("step %d argv mismatch:\n got: %v\nwant: %v", i, runner.calls[i].argv, want[i].argv)
		}
	}
	if !strings.Contains(buf.String(), "done.") {
		t.Errorf("output should end with 'done.'; got:\n%s", buf.String())
	}
}

func TestCAInstallApply_YesSkipsPrompt(t *testing.T) {
	cert := writeTempCert(t)
	runner := newFakeRunner()
	var buf bytes.Buffer
	// Empty stdin — would decline if the prompt were reached.
	err := applyInstall(&buf, strings.NewReader(""), platformLinuxFedora, cert, true, runner, privileged)
	if err != nil {
		t.Fatalf("apply --yes: %v\n%s", err, buf.String())
	}
	if len(runner.calls) != 2 {
		t.Errorf("Fedora has 2 install steps; runner saw %d: %+v", len(runner.calls), runner.calls)
	}
	if strings.Contains(buf.String(), "Proceed?") {
		t.Errorf("--yes should suppress the prompt; got prompt in output:\n%s", buf.String())
	}
}

func TestCAInstallApply_StepFailureAbortsSequence(t *testing.T) {
	cert := writeTempCert(t)
	runner := newFakeRunner()
	runner.failAt = 0 // fail on the first step
	var buf bytes.Buffer
	err := applyInstall(&buf, strings.NewReader(""), platformLinuxDebian, cert, true, runner, privileged)
	if err == nil {
		t.Fatal("expected error when first step fails")
	}
	if !strings.Contains(err.Error(), "step 1") {
		t.Errorf("error should name the failing step number; got: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Errorf("subsequent steps must not run after a failure; saw %d calls: %+v", len(runner.calls), runner.calls)
	}
	if !runner.failBoom {
		t.Error("expected failure path to fire")
	}
}

func TestInstallStepsFor_AllSupportedPlatforms(t *testing.T) {
	cases := []platform{
		platformLinuxDebian, platformLinuxFedora, platformLinuxAlpine, platformLinuxArch, platformDarwin,
	}
	for _, p := range cases {
		t.Run(string(p), func(t *testing.T) {
			steps := installStepsFor(p, "/etc/trollbridge/ca.crt")
			if len(steps) == 0 {
				t.Fatalf("platform %q has no apply steps", p)
			}
			for i, s := range steps {
				if len(s.argv) == 0 {
					t.Errorf("step %d for %q has empty argv", i, p)
				}
				if s.argv[0] == "sudo" {
					t.Errorf("step %d for %q starts with sudo; argv must assume root: %v", i, p, s.argv)
				}
				if s.desc == "" {
					t.Errorf("step %d for %q has empty description", i, p)
				}
			}
		})
	}
}

func TestInstallStepsFor_RefusedPlatformsHaveNoSteps(t *testing.T) {
	for _, p := range []platform{platformWindows, platformLinuxUnknown, platformUnknown} {
		if got := installStepsFor(p, "/x"); got != nil {
			t.Errorf("platform %q should return nil steps (refusal class); got %+v", p, got)
		}
	}
}

func TestConfirmYes(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"y\n", true},
		{"Y\n", true},
		{"yes\n", true},
		{"YES\n", true},
		{" y \n", true},
		{"n\n", false},
		{"no\n", false},
		{"", false},
		{"\n", false},
		{"maybe\n", false},
	}
	for _, c := range cases {
		t.Run(strings.TrimSpace(c.in)+"_"+map[bool]string{true: "yes", false: "no"}[c.want], func(t *testing.T) {
			got := confirmYes(strings.NewReader(c.in))
			if got != c.want {
				t.Errorf("confirmYes(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func equalArgv(a, b []string) bool {
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
