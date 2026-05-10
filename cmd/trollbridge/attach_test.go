package main

import (
	"strings"
	"testing"
)

// TestAttachCmd_RegisteredWithRoot closes #37 by asserting that the
// rename tui→attach actually landed: the cobra root finds `attach`,
// and the legacy `tui` command no longer resolves.
func TestAttachCmd_RegisteredWithRoot(t *testing.T) {
	root := newRootCmd()

	c, _, err := root.Find([]string{"attach"})
	if err != nil {
		t.Fatalf("root.Find(attach) returned error: %v", err)
	}
	if c == nil || c.Use != "attach" {
		t.Errorf("attach command not registered; got %+v", c)
	}

	c, _, err = root.Find([]string{"tui"})
	if err == nil && c != nil && c.Use == "tui" {
		t.Errorf("legacy `tui` command should be gone; got %+v", c)
	}
}

// TestAttachCmd_HelpDescribesUnifiedUI verifies the help text names
// the two-pane shape so an operator who reads --help understands
// what they will see.
func TestAttachCmd_HelpDescribesUnifiedUI(t *testing.T) {
	cmd := newAttachCmd()
	for _, want := range []string{"two-pane", "Tab", "approve", "deny"} {
		if !strings.Contains(cmd.Long, want) {
			t.Errorf("attach long help missing %q in:\n%s", want, cmd.Long)
		}
	}
}
