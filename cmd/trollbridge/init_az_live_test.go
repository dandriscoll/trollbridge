//go:build live_az

// Live `az` integration tests. Opt-in via the `live_az` build tag;
// not run in default CI. Exercises the real `az` binary against a
// known-stable Azure tenant so the wizard's parsers stay locked to
// Azure's actual JSON shape (closes #148).
//
// Required environment:
//
//   - `az` on PATH and logged in (`az login`).
//   - A subscription with read access to Cognitive Services / OpenAI
//     accounts. The test does NOT create or modify Azure resources;
//     it only enumerates and inspects.
//
// Usage:
//
//   go test -tags=live_az ./cmd/trollbridge/ -run TestLiveAz -v
//
// Failure shape this prevents: Azure changes the JSON shape between
// releases. The fixture-based unit tests still pass, integration
// silently breaks for real-world operators running the init wizard.

package main

import (
	"os/exec"
	"testing"
)

// TestLiveAz_PrerequisitesPresent is the single sentinel: skipping
// when az isn't reachable lets the lane be exercised in environments
// that don't have az without polluting `--list -v` output with
// confusing FAILs. The other lanes below assume this passes.
func TestLiveAz_PrerequisitesPresent(t *testing.T) {
	if !azInPath() {
		t.Skip("`az` not on PATH; install via https://learn.microsoft.com/cli/azure/install-azure-cli")
	}
	if !azLoggedIn() {
		t.Skip("`az account show` failed; run `az login` and retry")
	}
}

// TestLiveAz_AccountListJSONShape exercises `az cognitiveservices
// account list` against a real subscription and asserts the JSON
// parses into the `azAccount` struct the wizard consumes. The
// parser silently tolerates extra fields per encoding/json defaults,
// so the failure shape this guards is "a renamed or removed field
// the wizard reads."
func TestLiveAz_AccountListJSONShape(t *testing.T) {
	if !azInPath() || !azLoggedIn() {
		t.Skip("live az prerequisites missing (see TestLiveAz_PrerequisitesPresent)")
	}
	accounts, err := listAOAIAccounts()
	if err != nil {
		t.Fatalf("listAOAIAccounts on live tenant: %v", err)
	}
	// Schema invariant: every account the wizard surfaces must
	// have a parseable name + kind. Subscriptions with no OpenAI
	// accounts return an empty slice — that's a valid passing
	// shape; the wizard handles empty-list separately.
	for i, a := range accounts {
		if a.Name == "" {
			t.Errorf("account[%d]: empty Name field; raw json shape may have drifted", i)
		}
		if a.Kind != "OpenAI" {
			t.Errorf("account[%d]: Kind = %q, want OpenAI (filter regression)", i, a.Kind)
		}
	}
}

// TestLiveAz_DeploymentListJSONShape: if the live tenant has at
// least one OpenAI account, enumerate its deployments and assert
// the JSON parses. Skips quietly when the tenant has none — that's
// a real-world possibility and not a test failure.
func TestLiveAz_DeploymentListJSONShape(t *testing.T) {
	if !azInPath() || !azLoggedIn() {
		t.Skip("live az prerequisites missing (see TestLiveAz_PrerequisitesPresent)")
	}
	accounts, err := listAOAIAccounts()
	if err != nil {
		t.Fatalf("listAOAIAccounts: %v", err)
	}
	if len(accounts) == 0 {
		t.Skip("no OpenAI accounts on this subscription; deployment-shape lane has nothing to exercise")
	}
	first := accounts[0]
	deps, err := listAOAIDeployments(first.Name, first.ResourceGroup)
	if err != nil {
		t.Fatalf("listAOAIDeployments on %s/%s: %v", first.ResourceGroup, first.Name, err)
	}
	for i, d := range deps {
		if d.Name == "" {
			t.Errorf("deployment[%d]: empty Name field; raw json shape may have drifted", i)
		}
	}
}

// TestLiveAz_VersionParses sanity-checks that `az --version` itself
// returns interpretable output. Catches the case where az is on
// PATH but a broken install returns garbled output that the
// wizard's downstream parsers can't handle. Cheap; runs always
// when the gates pass.
func TestLiveAz_VersionParses(t *testing.T) {
	if !azInPath() {
		t.Skip("`az` not on PATH")
	}
	out, err := exec.Command("az", "--version").Output()
	if err != nil {
		t.Fatalf("az --version: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("az --version returned empty output")
	}
}
