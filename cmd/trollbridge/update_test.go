package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestUpdateCmd_Windows_PrintsManualInstructions(t *testing.T) {
	prev := updateGOOS
	updateGOOS = "windows"
	defer func() { updateGOOS = prev }()

	prevRunner := updateRunner
	updateRunner = func(stdout, stderr io.Writer) error {
		t.Fatalf("installer must not be invoked on windows; got call")
		return nil
	}
	defer func() { updateRunner = prevRunner }()

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
	prevRunner := updateRunner
	updateRunner = func(stdout, stderr io.Writer) error {
		called = true
		_, _ = stdout.Write([]byte("installer ran\n"))
		return nil
	}
	defer func() { updateRunner = prevRunner }()

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

	prevRunner := updateRunner
	updateRunner = func(stdout, stderr io.Writer) error {
		return errors.New("curl: network unreachable")
	}
	defer func() { updateRunner = prevRunner }()

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
