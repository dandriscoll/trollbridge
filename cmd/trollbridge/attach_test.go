package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/config"
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

// TestPrintAttachCertError pins the #46 contract: when the mTLS
// preflight fails, the operator sees a multi-line stderr message
// that names the cause, all three paths tried, whether each came
// from a TROLLBRIDGE_CONTROLLER_* env override, and the next-step
// commands. None of this can be hidden by terminal-width
// truncation — it goes to stderr before the TUI takes over.
func TestPrintAttachCertError(t *testing.T) {
	t.Setenv("TROLLBRIDGE_CONTROLLER_CERT", "/etc/trollbridge/op.crt")
	t.Setenv("TROLLBRIDGE_CONTROLLER_KEY", "")
	t.Setenv("TROLLBRIDGE_CONTROLLER_CA", "")
	cfg := &config.Config{}
	cfg.Interception.CA.CertPath = "/etc/trollbridge/ca.crt"

	var buf bytes.Buffer
	printAttachCertError(&buf, cfg, errors.New("load operator cert (...): no such file or directory"))
	out := buf.String()

	for _, want := range []string{
		"trollbridge attach: cannot reach the control plane.",
		"cause:",
		"no such file or directory",
		"paths tried:",
		"cert: /etc/trollbridge/op.crt (from $TROLLBRIDGE_CONTROLLER_CERT)",
		"key:",
		"ca:   /etc/trollbridge/ca.crt",
		"fix:",
		"trollbridge ca client-cert <name>",
		"~/.trollbridge/",
		"TROLLBRIDGE_CONTROLLER_CERT/_KEY",
		"Re-run `trollbridge attach`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	// The unset env vars should NOT carry the "(from $...)" suffix
	// — that suffix tells the operator their override is in effect,
	// so it must only fire when the env var is set.
	if strings.Contains(out, "(from $TROLLBRIDGE_CONTROLLER_KEY)") {
		t.Errorf("unset env var should not carry override annotation; got:\n%s", out)
	}
	if strings.Contains(out, "(from $TROLLBRIDGE_CONTROLLER_CA)") {
		t.Errorf("unset env var should not carry override annotation; got:\n%s", out)
	}
}
