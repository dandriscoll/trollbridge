package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

// init_az.go drives the az-CLI integration for `trollbridge init`'s
// AOAI provider branch (closes #132). When the operator picks aoai
// AND az is installed AND a subscription is logged in, the wizard
// offers to find or create an Azure OpenAI deployment automatically
// — populating the endpoint URL / model / (user-mode) API key from
// the chosen or created resource.
//
// Detection rule: `az --version` succeeds (PATH check) AND
// `az account show` succeeds (auth check). PATH-fail → silent
// skip. PATH-pass + auth-fail → one-line transcript hint
// suggesting `az login` + re-run, then silent fall-through
// (closes #136). PATH-pass + auth-pass → full flow.

// azExec is the single subprocess entry point. Tests replace this
// with a canned-JSON returner; production routes through `exec.Command("az", ...)`.
var azExec = func(args ...string) ([]byte, error) {
	out, err := exec.Command("az", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			// Surface stderr too — az's helpful error messages live
			// there. Wrap so the orchestrator can route them to the
			// operator.
			return nil, fmt.Errorf("az %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("az %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// azInPath returns true when the `az` binary is reachable and
// `az --version` succeeds. Single-purpose probe; callers that
// need to discriminate PATH-fail from auth-fail use this plus
// azLoggedIn instead of azAvailable.
func azInPath() bool {
	_, err := azExec("--version")
	return err == nil
}

// azLoggedIn returns true when `az account show` succeeds —
// i.e., the operator has an active subscription. Assumes
// azInPath is true; if az is not in PATH the call fails with
// the same shape as not-logged-in, so callers should gate this
// on azInPath when they need to distinguish the two states.
func azLoggedIn() bool {
	_, err := azExec("account", "show", "-o", "json")
	return err == nil
}

// azAvailable returns true only when both az is reachable AND a
// subscription is logged in. Kept as a convenience for callers
// (and tests) that only need the binary "shortcut usable?"
// answer; runAzFlow uses the split helpers instead so it can
// emit the not-logged-in hint.
func azAvailable() bool {
	return azInPath() && azLoggedIn()
}

// azAccount is the trimmed JSON shape of `az cognitiveservices
// account list -o json`. Only the fields the wizard reads are
// declared; extra fields are ignored by Go's encoding/json.
type azAccount struct {
	Name          string         `json:"name"`
	ResourceGroup string         `json:"resourceGroup"`
	Kind          string         `json:"kind"`
	Location      string         `json:"location"`
	Properties    azAccountProps `json:"properties"`
}

type azAccountProps struct {
	Endpoint string `json:"endpoint"`
}

// azDeployment is the trimmed shape of `az cognitiveservices
// account deployment list -o json`.
type azDeployment struct {
	Name       string            `json:"name"`
	Properties azDeploymentProps `json:"properties"`
}

type azDeploymentProps struct {
	Model azDeploymentModel `json:"model"`
}

type azDeploymentModel struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// azKeys is the trimmed shape of `az cognitiveservices account
// keys list -o json`.
type azKeys struct {
	Key1 string `json:"key1"`
	Key2 string `json:"key2"`
}

// azResourceGroup is the trimmed shape of `az group list -o json`.
type azResourceGroup struct {
	Name     string `json:"name"`
	Location string `json:"location"`
}

// listAOAIAccounts enumerates the operator's OpenAI accounts in the
// active subscription. Filters az's full Cognitive Services list to
// `kind == "OpenAI"`.
func listAOAIAccounts() ([]azAccount, error) {
	body, err := azExec("cognitiveservices", "account", "list", "-o", "json")
	if err != nil {
		return nil, err
	}
	var all []azAccount
	if err := json.Unmarshal(body, &all); err != nil {
		return nil, fmt.Errorf("decode az cognitiveservices account list: %w", err)
	}
	filtered := make([]azAccount, 0, len(all))
	for _, a := range all {
		if a.Kind == "OpenAI" {
			filtered = append(filtered, a)
		}
	}
	return filtered, nil
}

// listAOAIDeployments enumerates the deployments under a given
// OpenAI account.
func listAOAIDeployments(account, resourceGroup string) ([]azDeployment, error) {
	body, err := azExec("cognitiveservices", "account", "deployment", "list",
		"-n", account, "-g", resourceGroup, "-o", "json")
	if err != nil {
		return nil, err
	}
	var deps []azDeployment
	if err := json.Unmarshal(body, &deps); err != nil {
		return nil, fmt.Errorf("decode az ... deployment list: %w", err)
	}
	return deps, nil
}

// fetchAOAIKey returns key1 for the named OpenAI account. The wizard
// only requests this in user-mode (daemon-mode operators install
// keys separately).
func fetchAOAIKey(account, resourceGroup string) (string, error) {
	body, err := azExec("cognitiveservices", "account", "keys", "list",
		"-n", account, "-g", resourceGroup, "-o", "json")
	if err != nil {
		return "", err
	}
	var k azKeys
	if err := json.Unmarshal(body, &k); err != nil {
		return "", fmt.Errorf("decode az ... keys list: %w", err)
	}
	if k.Key1 == "" {
		return "", fmt.Errorf("az ... keys list: key1 empty")
	}
	return k.Key1, nil
}

// listResourceGroups enumerates the operator's resource groups for
// the create flow's group-selection prompt.
func listResourceGroups() ([]azResourceGroup, error) {
	body, err := azExec("group", "list", "-o", "json")
	if err != nil {
		return nil, err
	}
	var groups []azResourceGroup
	if err := json.Unmarshal(body, &groups); err != nil {
		return nil, fmt.Errorf("decode az group list: %w", err)
	}
	return groups, nil
}

// createResourceGroup creates a resource group when the operator
// types a name that does not already exist.
func createResourceGroup(name, location string) error {
	if _, err := azExec("group", "create", "-n", name, "-l", location, "-o", "json"); err != nil {
		return err
	}
	return nil
}

// createAOAIAccount provisions a new Cognitive Services OpenAI
// account. Synchronous in az's default mode (blocks until ready,
// usually ~30s).
func createAOAIAccount(name, resourceGroup, location string) (azAccount, error) {
	body, err := azExec("cognitiveservices", "account", "create",
		"-n", name, "-g", resourceGroup, "--kind", "OpenAI", "--sku", "S0", "-l", location, "-o", "json")
	if err != nil {
		return azAccount{}, err
	}
	var a azAccount
	if err := json.Unmarshal(body, &a); err != nil {
		return azAccount{}, fmt.Errorf("decode az ... account create: %w", err)
	}
	return a, nil
}

// createAOAIDeploymentResource provisions a new deployment within an
// existing OpenAI account.
func createAOAIDeploymentResource(account, resourceGroup, deploymentName, model, modelVersion string) (azDeployment, error) {
	args := []string{
		"cognitiveservices", "account", "deployment", "create",
		"-n", account, "-g", resourceGroup,
		"--deployment-name", deploymentName,
		"--model-name", model,
		"--model-format", "OpenAI",
	}
	if modelVersion != "" {
		args = append(args, "--model-version", modelVersion)
	}
	args = append(args, "-o", "json")
	body, err := azExec(args...)
	if err != nil {
		return azDeployment{}, err
	}
	var d azDeployment
	if err := json.Unmarshal(body, &d); err != nil {
		return azDeployment{}, fmt.Errorf("decode az ... deployment create: %w", err)
	}
	return d, nil
}

// aoaiEndpointURL composes the operator-facing endpoint URL the
// trollbridge AOAI provider expects. The path includes the
// deployment name; the api-version is pinned to match the
// example-config convention.
func aoaiEndpointURL(accountEndpoint, deployment string) string {
	base := strings.TrimRight(accountEndpoint, "/")
	return fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=2024-02-15-preview",
		base, deployment)
}

// runAzFlow is the orchestrator. Called from runInteractiveInit
// after the operator picks aoai. Returns without modifying ans when
// az is not available OR the operator declines. On success, ans's
// llmEndpoint / llmModel / (user-mode) llmKey are pre-filled.
//
// The function is intentionally re-entrant on per-step failures:
// each az call's error is surfaced to the operator and the
// orchestrator returns to its choice prompt so the operator can
// retry or pick a different path.
func runAzFlow(r *bufio.Reader, out io.Writer, ans *initAnswers) {
	if !azInPath() {
		// Silent skip: the operator has no `az`. The existing
		// manual prompts that follow are unchanged.
		return
	}
	if !azLoggedIn() {
		// `az` is here but the operator is not authenticated.
		// Surface the activation step so they know the shortcut
		// is one `az login` away, then fall through silently to
		// the manual prompts (closes #136).
		fmt.Fprintln(out)
		fmt.Fprintln(out, "   → az detected but not authenticated; run `az login`, then re-run `trollbridge init` to use the AOAI shortcut.")
		return
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "   ── Azure CLI detected. trollbridge can find an existing AOAI")
	fmt.Fprintln(out, "      deployment or create a new one — or skip if you'd rather")
	fmt.Fprintln(out, "      type the endpoint and key manually.")
	for {
		choice := promptChoice(r, out,
			"   az action",
			[]string{"find", "create", "skip"},
			"skip",
		)
		switch choice {
		case "skip":
			fmt.Fprintln(out)
			return
		case "find":
			if azFindFlow(r, out, ans) {
				return
			}
			// Loop back: the operator can retry, pick create, or skip.
		case "create":
			if azCreateFlow(r, out, ans) {
				return
			}
		}
	}
}

// azFindFlow lists OpenAI accounts and deployments, lets the
// operator pick one, and populates ans. Returns true when ans was
// populated; false (and surfaces the error inline) on any failure
// so the orchestrator can re-prompt.
func azFindFlow(r *bufio.Reader, out io.Writer, ans *initAnswers) bool {
	accounts, err := listAOAIAccounts()
	if err != nil {
		fmt.Fprintf(out, "   (az error listing OpenAI accounts: %v)\n", err)
		return false
	}
	if len(accounts) == 0 {
		fmt.Fprintln(out, "   (no OpenAI accounts found in the active subscription; try `create` instead.)")
		return false
	}
	acct, ok := pickAccount(r, out, accounts)
	if !ok {
		return false
	}
	deps, err := listAOAIDeployments(acct.Name, acct.ResourceGroup)
	if err != nil {
		fmt.Fprintf(out, "   (az error listing deployments: %v)\n", err)
		return false
	}
	if len(deps) == 0 {
		fmt.Fprintf(out, "   (account %q has no deployments yet; try `create` or pick another account.)\n", acct.Name)
		return false
	}
	dep, ok := pickDeployment(r, out, deps)
	if !ok {
		return false
	}
	return applyAzSelection(r, out, ans, acct, dep.Name, dep.Properties.Model.Name)
}

// azCreateFlow walks the operator through creating a new OpenAI
// account and a deployment under it. Returns true when ans was
// populated; false on any failure (with the error surfaced inline)
// so the orchestrator can re-prompt.
func azCreateFlow(r *bufio.Reader, out io.Writer, ans *initAnswers) bool {
	// Resource group: list existing AND let the operator type a
	// new name. A typed name that does not match any existing
	// group is created on demand.
	groups, err := listResourceGroups()
	if err != nil {
		fmt.Fprintf(out, "   (az error listing resource groups: %v)\n", err)
		return false
	}
	rgName, rgLocation := pickOrTypeResourceGroup(r, out, groups)
	if rgName == "" {
		return false
	}
	location := promptString(r, out, "   location", rgLocation)
	if location == "" {
		location = "eastus"
	}
	if !rgExists(groups, rgName) {
		fmt.Fprintf(out, "   creating resource group %q in %q ...\n", rgName, location)
		if err := createResourceGroup(rgName, location); err != nil {
			fmt.Fprintf(out, "   (az error creating resource group: %v)\n", err)
			return false
		}
	}
	accountName, err := promptRequiredString(r, out, "   AOAI account name (3-24 chars, lowercase + digits)")
	if err != nil {
		fmt.Fprintf(out, "   (%v)\n", err)
		return false
	}
	deploymentName := promptString(r, out, "   deployment name", "gpt-4o-mini")
	model := promptString(r, out, "   model", "gpt-4o-mini")
	modelVersion := promptString(r, out, "   model version (blank = latest)", "")

	fmt.Fprintf(out, "   creating AOAI account %q in resource group %q (~30s) ...\n", accountName, rgName)
	acct, err := createAOAIAccount(accountName, rgName, location)
	if err != nil {
		fmt.Fprintf(out, "   (az error creating account: %v)\n", err)
		return false
	}
	fmt.Fprintf(out, "   creating deployment %q (model %q) ...\n", deploymentName, model)
	if _, err := createAOAIDeploymentResource(accountName, rgName, deploymentName, model, modelVersion); err != nil {
		fmt.Fprintf(out, "   (az error creating deployment: %v)\n", err)
		return false
	}
	return applyAzSelection(r, out, ans, acct, deploymentName, model)
}

// applyAzSelection commits the chosen account + deployment into the
// wizard's answers. Endpoint URL is composed from account.endpoint
// + deployment name; the model name is the deployment's model;
// user-mode flows additionally fetch the API key.
func applyAzSelection(r *bufio.Reader, out io.Writer, ans *initAnswers, acct azAccount, deployment, model string) bool {
	ans.llmEndpoint = aoaiEndpointURL(acct.Properties.Endpoint, deployment)
	if model != "" {
		ans.llmModel = model
	}
	if ans.installMode == "user" {
		key, err := fetchAOAIKey(acct.Name, acct.ResourceGroup)
		if err != nil {
			fmt.Fprintf(out, "   (az error fetching key: %v; you can paste it at the API-key prompt below)\n", err)
		} else {
			ans.llmKey = key
		}
	}
	fmt.Fprintf(out, "   ✓ AOAI deployment ready: %s\n", ans.llmEndpoint)
	if ans.installMode == "daemon" {
		fmt.Fprintf(out, "   (daemon-mode: install the API key separately on the proxy host;\n")
		fmt.Fprintf(out, "     `az cognitiveservices account keys list -n %s -g %s` shows it.)\n", acct.Name, acct.ResourceGroup)
	}
	fmt.Fprintln(out)
	return true
}

// pickAccount asks the operator to choose from a numbered list of
// accounts. Returns (chosen, true) on success or (zero, false) on
// invalid/abandoned input.
func pickAccount(r *bufio.Reader, out io.Writer, accounts []azAccount) (azAccount, bool) {
	fmt.Fprintln(out, "   OpenAI accounts in active subscription:")
	for i, a := range accounts {
		fmt.Fprintf(out, "     [%d] %s  (group=%s, location=%s)\n", i+1, a.Name, a.ResourceGroup, a.Location)
	}
	return pickFromList(r, out, "   pick an account by number", len(accounts), accounts)
}

// pickDeployment asks the operator to choose from a numbered list
// of deployments under the chosen account.
func pickDeployment(r *bufio.Reader, out io.Writer, deps []azDeployment) (azDeployment, bool) {
	fmt.Fprintln(out, "   deployments in this account:")
	for i, d := range deps {
		fmt.Fprintf(out, "     [%d] %s  (model=%s %s)\n", i+1, d.Name, d.Properties.Model.Name, d.Properties.Model.Version)
	}
	return pickFromList(r, out, "   pick a deployment by number", len(deps), deps)
}

// pickFromList is the shared 1-indexed picker for the find flow.
// Generic over the element type via a small helper so the caller
// can return its own typed zero value on cancel.
func pickFromList[T any](r *bufio.Reader, out io.Writer, label string, n int, items []T) (T, bool) {
	var zero T
	for attempt := 0; attempt < 3; attempt++ {
		raw := promptString(r, out, label, "1")
		idx, err := strconv.Atoi(raw)
		if err != nil || idx < 1 || idx > n {
			fmt.Fprintf(out, "   (please pick a number from 1 to %d)\n", n)
			continue
		}
		return items[idx-1], true
	}
	fmt.Fprintln(out, "   (too many invalid attempts; returning to az action)")
	return zero, false
}

// pickOrTypeResourceGroup combines the find-flow numbered list with
// a free-text option. The operator can pick an existing group by
// number, type an existing group's name, or type a new name to be
// created.
func pickOrTypeResourceGroup(r *bufio.Reader, out io.Writer, groups []azResourceGroup) (name, location string) {
	if len(groups) > 0 {
		fmt.Fprintln(out, "   existing resource groups:")
		for i, g := range groups {
			fmt.Fprintf(out, "     [%d] %s  (location=%s)\n", i+1, g.Name, g.Location)
		}
	}
	fmt.Fprintln(out, "   pick a number, type an existing group name, or type a new name to create")
	raw := promptString(r, out, "   resource group", "")
	if raw == "" {
		return "", ""
	}
	if idx, err := strconv.Atoi(raw); err == nil && idx >= 1 && idx <= len(groups) {
		return groups[idx-1].Name, groups[idx-1].Location
	}
	// Typed name: if it matches an existing group, return its
	// location; otherwise leave location blank so the next prompt
	// can collect it.
	for _, g := range groups {
		if g.Name == raw {
			return g.Name, g.Location
		}
	}
	return raw, ""
}

// rgExists reports whether the named resource group is already in
// the operator's list — drives the "create on demand" branch.
func rgExists(groups []azResourceGroup, name string) bool {
	for _, g := range groups {
		if g.Name == name {
			return true
		}
	}
	return false
}
