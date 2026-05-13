package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/updater"
)

func TestUpdateCmd_Windows_PrintsManualInstructions(t *testing.T) {
	prev := updateGOOS
	updateGOOS = "windows"
	defer func() { updateGOOS = prev }()

	prevRunner := updater.Run
	updater.Run = func(stdout, stderr io.Writer) error {
		t.Fatalf("installer must not be invoked on windows; got call")
		return nil
	}
	defer func() { updater.Run = prevRunner }()

	cmd := newUpdateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("expected nil err on windows branch; got: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "not yet supported on Windows") {
		t.Errorf("windows message missing cause; got: %s", got)
	}
	if !strings.Contains(got, "github.com/dandriscoll/trollbridge/releases/latest") {
		t.Errorf("windows message missing next-action URL; got: %s", got)
	}
}

func TestUpdateCmd_NonWindows_InvokesInstaller(t *testing.T) {
	prev := updateGOOS
	updateGOOS = "linux"
	defer func() { updateGOOS = prev }()

	called := false
	prevRunner := updater.Run
	updater.Run = func(stdout, stderr io.Writer) error {
		called = true
		_, _ = stdout.Write([]byte("installer ran\n"))
		return nil
	}
	defer func() { updater.Run = prevRunner }()

	cmd := newUpdateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("expected nil err; got: %v", err)
	}
	if !called {
		t.Errorf("installer runner was not invoked")
	}
	if !strings.Contains(out.String(), "installer ran") {
		t.Errorf("installer stdout was not wired through; got: %s", out.String())
	}
}

func TestUpdateCmd_InstallerFailure_SurfacesAsRuntimeErr(t *testing.T) {
	prev := updateGOOS
	updateGOOS = "linux"
	defer func() { updateGOOS = prev }()

	prevRunner := updater.Run
	updater.Run = func(stdout, stderr io.Writer) error {
		return errors.New("curl: network unreachable")
	}
	defer func() { updater.Run = prevRunner }()

	cmd := newUpdateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatalf("expected installer failure to surface; got nil")
	}
	var re *runtimeErr
	if !errors.As(err, &re) {
		t.Errorf("expected runtimeErr so exitCodeFor returns 2; got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "curl: network unreachable") {
		t.Errorf("installer error not preserved in message; got: %v", err)
	}
}

func TestUpdateCmd_WiredUnderOperateGroup(t *testing.T) {
	root := newRootCmd()
	var found *cobraCmdRef
	for _, c := range root.Commands() {
		if c.Name() == "update" {
			found = &cobraCmdRef{name: c.Name(), groupID: c.GroupID}
			break
		}
	}
	if found == nil {
		t.Fatalf("update command not registered under root")
	}
	if found.groupID != "operate" {
		t.Errorf("update grouped under %q; want %q", found.groupID, "operate")
	}
}

type cobraCmdRef struct {
	name    string
	groupID string
}

// TestUpdateCmd_CheckFlag_PrintsLatestAndCurrent closes #102 part 2:
// `trollbridge update --check` HEAD-fetches LatestReleaseURL, parses
// the redirect's tag, and prints current vs latest WITHOUT invoking
// the installer.
func TestUpdateCmd_CheckFlag_PrintsLatestAndCurrent(t *testing.T) {
	prevRunner := updater.Run
	updater.Run = func(stdout, stderr io.Writer) error {
		t.Fatalf("--check must not invoke the installer")
		return nil
	}
	defer func() { updater.Run = prevRunner }()

	prevCheck := updater.CheckLatest
	updater.CheckLatest = func() (string, error) {
		return "v9.9.9", nil
	}
	defer func() { updater.CheckLatest = prevCheck }()

	cmd := newUpdateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--check"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := out.String()
	for _, want := range []string{"current:", "latest:", "v9.9.9"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in --check output:\n%s", want, got)
		}
	}
}

// TestUpdateCmd_CheckFlag_FailureSurfaces: when CheckLatest returns
// an error (network down, GitHub layout changed), --check fails with
// a runtimeErr that name the cause.
func TestUpdateCmd_CheckFlag_FailureSurfaces(t *testing.T) {
	prevCheck := updater.CheckLatest
	updater.CheckLatest = func() (string, error) {
		return "", errors.New("dial tcp: connection refused")
	}
	defer func() { updater.CheckLatest = prevCheck }()

	cmd := newUpdateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--check"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	var re *runtimeErr
	if !errors.As(err, &re) {
		t.Errorf("expected runtimeErr; got %T", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error must preserve underlying cause; got: %v", err)
	}
}

// TestUpdateCmd_FailureClassifiedHintAppears: when the installer
// returns an updater.Error, the CLI surfaces the class + hint above
// the wrapped error so the operator's first read names the next
// action. Closes #102 part 1's CLI wiring.
func TestUpdateCmd_FailureClassifiedHintAppears(t *testing.T) {
	prev := updateGOOS
	updateGOOS = "linux"
	defer func() { updateGOOS = prev }()

	prevRunner := updater.Run
	updater.Run = func(stdout, stderr io.Writer) error {
		return &updater.Error{
			Underlying: errors.New("exit status 6"),
			Class:      updater.FailureNetwork,
			Hint:       "run `curl -v https://trollbridge.dev/install.sh` to debug network",
		}
	}
	defer func() { updater.Run = prevRunner }()

	cmd := newUpdateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	got := out.String()
	if !strings.Contains(got, "trollbridge update failed (network)") {
		t.Errorf("missing classification line; got: %s", got)
	}
	if !strings.Contains(got, "hint:") {
		t.Errorf("missing hint line; got: %s", got)
	}
}
