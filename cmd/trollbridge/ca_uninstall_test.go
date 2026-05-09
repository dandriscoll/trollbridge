package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// recordRunner captures every step the apply path dispatches.
// Mirrors the existing pattern from ca_install_apply_test.go but
// kept local so the two suites can evolve independently.
type recordRunner struct {
	calls []installStep
	fail  error
}

func (r *recordRunner) run(step installStep, out io.Writer) error {
	r.calls = append(r.calls, step)
	if r.fail != nil {
		return r.fail
	}
	fmt.Fprintf(out, "[stub] %s\n", step.desc)
	return nil
}

// TestUninstallStepsFor_KnownPlatformsRemoveAndRebuild closes the
// happy-path coverage of issue #29: every supported platform's
// uninstall plan removes the destination cert and (where
// applicable) rebuilds the system trust store.
func TestUninstallStepsFor_KnownPlatformsRemoveAndRebuild(t *testing.T) {
	cases := map[platform]struct {
		wantContains []string
	}{
		platformLinuxDebian: {wantContains: []string{"rm", "/usr/local/share/ca-certificates/trollbridge-ca.crt", "update-ca-certificates"}},
		platformLinuxAlpine: {wantContains: []string{"rm", "/usr/local/share/ca-certificates/trollbridge-ca.crt", "update-ca-certificates"}},
		platformLinuxFedora: {wantContains: []string{"rm", "/etc/pki/ca-trust/source/anchors/trollbridge-ca.crt", "update-ca-trust"}},
		platformLinuxArch:   {wantContains: []string{"trust", "anchor", "--remove"}},
		platformDarwin:      {wantContains: []string{"security", "delete-certificate"}},
	}
	for p, want := range cases {
		t.Run(string(p), func(t *testing.T) {
			steps := uninstallStepsFor(p)
			if len(steps) == 0 {
				t.Fatalf("no steps for %s", p)
			}
			joined := ""
			for _, s := range steps {
				joined += " " + strings.Join(s.argv, " ")
			}
			for _, w := range want.wantContains {
				if !strings.Contains(joined, w) {
					t.Errorf("platform %s: missing token %q in argv set:\n%s", p, w, joined)
				}
			}
		})
	}
}

// TestUninstallStepsFor_WindowsAndUnknownReturnNil asserts the
// caller's contract: nil plan signals the apply path to fail with
// a platform-specific message instead of running an empty sequence.
func TestUninstallStepsFor_WindowsAndUnknownReturnNil(t *testing.T) {
	for _, p := range []platform{platformWindows, platformLinuxUnknown, platformUnknown} {
		if uninstallStepsFor(p) != nil {
			t.Errorf("platform %s should have no apply-mode plan", p)
		}
	}
}

// TestApplyUninstall_DispatchesEverySteppwhenConfirmed asserts the
// apply path runs every step under operator confirmation.
func TestApplyUninstall_DispatchesEverySteppwhenConfirmed(t *testing.T) {
	rec := &recordRunner{}
	var out bytes.Buffer
	if err := applyUninstall(&out, strings.NewReader("y\n"), platformLinuxDebian, "/etc/trollbridge/trollbridge-ca.crt", false, rec, func() bool { return true }); err != nil {
		t.Fatalf("applyUninstall: %v\n%s", err, out.String())
	}
	if got, want := len(rec.calls), 2; got != want {
		t.Errorf("dispatched steps = %d, want %d", got, want)
	}
}

// TestApplyUninstall_NotPrivileged_RefusesWithSudoHint asserts the
// privilege gate fires before any step runs.
func TestApplyUninstall_NotPrivileged_RefusesWithSudoHint(t *testing.T) {
	rec := &recordRunner{}
	var out bytes.Buffer
	err := applyUninstall(&out, strings.NewReader(""), platformLinuxDebian, "/etc/trollbridge/trollbridge-ca.crt", true, rec, func() bool { return false })
	if err == nil {
		t.Fatal("expected error from non-privileged caller")
	}
	if !strings.Contains(err.Error(), "sudo") {
		t.Errorf("error should suggest sudo; got: %v", err)
	}
	if len(rec.calls) != 0 {
		t.Errorf("no steps should have run before the privilege check; got %d", len(rec.calls))
	}
}

// TestApplyUninstall_StepFailureAborts asserts the sequence stops
// on the first failure and the error names the failing step.
func TestApplyUninstall_StepFailureAborts(t *testing.T) {
	rec := &recordRunner{fail: errors.New("simulated rm failure")}
	var out bytes.Buffer
	err := applyUninstall(&out, strings.NewReader("y\n"), platformLinuxDebian, "/etc/trollbridge/trollbridge-ca.crt", true, rec, func() bool { return true })
	if err == nil {
		t.Fatal("expected error from failing step")
	}
	if len(rec.calls) != 1 {
		t.Errorf("on first-step failure, only 1 step should have dispatched; got %d", len(rec.calls))
	}
}

// TestPrintUninstallHelp_DetectedPlatformOnly closes the
// non-apply branch.
func TestPrintUninstallHelp_DetectedPlatformOnly(t *testing.T) {
	var buf bytes.Buffer
	printUninstallHelp(&buf, "/etc/trollbridge/trollbridge-ca.crt", false, platformLinuxDebian)
	for _, want := range []string{
		"trollbridge CA uninstall",
		"sudo rm -f /usr/local/share/ca-certificates/trollbridge-ca.crt",
		"sudo update-ca-certificates --fresh",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q in help output:\n%s", want, buf.String())
		}
	}
}

// TestPrintUninstallHelp_AllPlatforms emits every supported set.
func TestPrintUninstallHelp_AllPlatforms(t *testing.T) {
	var buf bytes.Buffer
	printUninstallHelp(&buf, "/etc/trollbridge/trollbridge-ca.crt", true, platformLinuxDebian)
	for _, want := range []string{
		"Debian",
		"Fedora",
		"Alpine",
		"Arch",
		"macOS",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("--all-platforms output missing %q:\n%s", want, buf.String())
		}
	}
}
