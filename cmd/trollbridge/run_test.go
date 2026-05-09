package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestPrintRunStartupBanner_NamesAddrModeAndCommands closes issue #15:
// when `trollbridge run` starts on a TTY, the operator sees a one-
// screen "you're up — try this next" banner with the listen address,
// the policy mode, and copy-pasteable next-step commands.
func TestPrintRunStartupBanner_NamesAddrModeAndCommands(t *testing.T) {
	var buf bytes.Buffer
	printRunStartupBanner(&buf, "127.0.0.1:8080", "default-deny")
	out := buf.String()
	for _, want := range []string{
		"trollbridge is listening on 127.0.0.1:8080",
		"mode: default-deny",
		"trollbridge test https://example.com",
		"trollbridge env",
		"Ctrl-C",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("banner missing %q in:\n%s", want, out)
		}
	}
}

func TestPrintRunStartupBanner_ReflectsBindAddress(t *testing.T) {
	var buf bytes.Buffer
	printRunStartupBanner(&buf, "0.0.0.0:9090", "default-allow")
	out := buf.String()
	if !strings.Contains(out, "0.0.0.0:9090") {
		t.Errorf("banner did not reflect bind address; got:\n%s", out)
	}
	if !strings.Contains(out, "default-allow") {
		t.Errorf("banner did not reflect mode; got:\n%s", out)
	}
}
