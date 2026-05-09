package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestWarnLegacyDrawbridgeEnv_WarnsOnSetLegacyVar closes the
// happy-path branch of issue #26: an operator with a stale
// DRAWBRIDGE_* env var sees a stderr warning naming both the old
// var and the new one.
func TestWarnLegacyDrawbridgeEnv_WarnsOnSetLegacyVar(t *testing.T) {
	lookup := func(k string) (string, bool) {
		if k == "DRAWBRIDGE_LOG_LEVEL" {
			return "debug", true
		}
		return "", false
	}
	var buf bytes.Buffer
	warnLegacyDrawbridgeEnv(&buf, lookup)
	for _, want := range []string{
		"legacy DRAWBRIDGE_*",
		"DRAWBRIDGE_LOG_LEVEL",
		"TROLLBRIDGE_LOG_LEVEL",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q in:\n%s", want, buf.String())
		}
	}
}

// TestWarnLegacyDrawbridgeEnv_NoOpWhenNothingSet asserts the
// warning is suppressed for the common case (operator has never
// set any DRAWBRIDGE_* var).
func TestWarnLegacyDrawbridgeEnv_NoOpWhenNothingSet(t *testing.T) {
	lookup := func(string) (string, bool) { return "", false }
	var buf bytes.Buffer
	warnLegacyDrawbridgeEnv(&buf, lookup)
	if buf.Len() != 0 {
		t.Errorf("expected silence; got:\n%s", buf.String())
	}
}

// TestWarnLegacyDrawbridgeEnv_SuppressedWhenNewIsSet: when both old
// and new are set, the operator has already migrated; the legacy
// var is leftover. Don't nag.
func TestWarnLegacyDrawbridgeEnv_SuppressedWhenNewIsSet(t *testing.T) {
	lookup := func(k string) (string, bool) {
		if k == "DRAWBRIDGE_CONFIG" {
			return "/old/path", true
		}
		if k == "TROLLBRIDGE_CONFIG" {
			return "/new/path", true
		}
		return "", false
	}
	var buf bytes.Buffer
	warnLegacyDrawbridgeEnv(&buf, lookup)
	if buf.Len() != 0 {
		t.Errorf("when new var is set, the legacy warning should be suppressed; got:\n%s", buf.String())
	}
}

// TestWarnLegacyDrawbridgeEnv_ListsAllSetLegacyVars asserts that
// when several legacy vars are set, all of them appear in the
// warning (so the operator does not have to discover them one-by-one).
func TestWarnLegacyDrawbridgeEnv_ListsAllSetLegacyVars(t *testing.T) {
	set := map[string]string{
		"DRAWBRIDGE_LOG_LEVEL":      "debug",
		"DRAWBRIDGE_CONTROLLER_CERT": "/etc/old.crt",
		"DRAWBRIDGE_CONTROLLER_KEY":  "/etc/old.key",
	}
	lookup := func(k string) (string, bool) {
		v, ok := set[k]
		return v, ok
	}
	var buf bytes.Buffer
	warnLegacyDrawbridgeEnv(&buf, lookup)
	for k := range set {
		if !strings.Contains(buf.String(), k) {
			t.Errorf("warning missing %q (operator wouldn't know to migrate it):\n%s", k, buf.String())
		}
	}
}
