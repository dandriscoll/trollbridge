package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// isTerminal wraps golang.org/x/term so init_interactive.go has a
// single seam for the TTY check (and tests that need to stub it
// can swap this var rather than the whole stdin shape).
var isTerminal = func(fd int) bool { return term.IsTerminal(fd) }

// initAnswers carries the result of the interactive `init` flow.
// `applyAnswers` consumes this to render the final YAML; `init.go`
// consumes it to decide whether to chain into ca.Init / write the
// LLM key file.
type initAnswers struct {
	topology     string // "laptop" | "incus-vm" | "sidecar" | "host-daemon"
	mode         string // "default-deny" | "default-allow" | "default-ask"
	interception bool
	llmEnabled   bool
	llmProvider  string // "anthropic" | "aoai" | <other string>
	llmModel     string
	llmKeyPath   string
	llmKey       string // present only if llmEnabled; the file gets written separately
}

// proxyBindFor maps a topology choice to the proxy bind string.
// Laptop and sidecar share-loopback share lo:8080; VM and daemon
// need to listen on all interfaces because the client is in a
// separate network namespace.
func proxyBindFor(topology string) string {
	switch topology {
	case "incus-vm", "host-daemon":
		return "all:8080"
	default:
		return "lo:8080"
	}
}

// runInteractiveInit drives the four-section prompt flow. It is
// pure with respect to the supplied io.Reader / io.Writer — no
// global state, no os.Stdin reads. The return is the answers
// struct; the caller materializes side effects (writing files,
// chaining into ca.Init).
func runInteractiveInit(in io.Reader, out io.Writer) (initAnswers, error) {
	r := bufio.NewReader(in)
	ans := initAnswers{
		topology:    "laptop",
		mode:        "default-ask",
		llmProvider: "anthropic",
		llmModel:    "claude-opus-4-7",
		llmKeyPath:  "/etc/trollbridge/llm.key",
	}

	fmt.Fprintln(out, "trollbridge init: guided setup. Press return to accept defaults shown in [brackets].")
	fmt.Fprintln(out)

	// 1. Topology
	fmt.Fprintln(out, "1) Where will trollbridge run?")
	ans.topology = promptChoice(r, out,
		"   topology",
		[]string{"laptop", "incus-vm", "sidecar", "host-daemon"},
		ans.topology,
	)
	fmt.Fprintf(out, "   → proxy bind: %s\n\n", proxyBindFor(ans.topology))

	// 2. Mode
	fmt.Fprintln(out, "2) What policy posture should the proxy enforce?")
	fmt.Fprintln(out, "   default-deny  — only listed hosts forward; everything else is blocked.")
	fmt.Fprintln(out, "   default-allow — only blocklisted hosts are denied; audit log captures the rest.")
	fmt.Fprintln(out, "   default-ask   — unmatched requests are held for advisor or operator approval.")
	ans.mode = promptChoice(r, out,
		"   mode",
		[]string{"default-deny", "default-allow", "default-ask"},
		ans.mode,
	)
	fmt.Fprintln(out)

	// 3. TLS interception
	fmt.Fprintln(out, "3) Enable TLS interception? (lets trollbridge see HTTPS request paths/bodies; requires installing a CA in the client trust store.)")
	ans.interception = promptYesNo(r, out, "   interception", false)
	if ans.interception {
		fmt.Fprintln(out, "   → trollbridge will generate a CA at ./trollbridge-ca.{crt,key} after writing the config.")
	}
	fmt.Fprintln(out)

	// 4. LLM advisor
	fmt.Fprintln(out, "4) Enable the LLM advisor? (classifies ambiguous requests when policy says ask_llm.)")
	ans.llmEnabled = promptYesNo(r, out, "   advisor", false)
	if ans.llmEnabled {
		ans.llmProvider = promptChoice(r, out,
			"   provider",
			[]string{"anthropic", "aoai", "other"},
			ans.llmProvider,
		)
		ans.llmModel = promptString(r, out, "   model", ans.llmModel)
		ans.llmKeyPath = promptString(r, out, "   API key path (will be written with mode 0600)", ans.llmKeyPath)
		key, err := promptSecret(r, out, "   API key (paste; will not be echoed back)")
		if err != nil {
			return ans, err
		}
		ans.llmKey = key
	}
	fmt.Fprintln(out)

	return ans, nil
}

// promptChoice asks the operator to pick from a fixed list. Empty
// input accepts the default; an unknown choice re-prompts up to
// three times before falling back to the default with a warning.
func promptChoice(r *bufio.Reader, out io.Writer, label string, choices []string, def string) string {
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintf(out, "%s (%s) [%s]: ", label, strings.Join(choices, " / "), def)
		line, err := r.ReadString('\n')
		v := strings.TrimSpace(line)
		if v == "" {
			return def
		}
		for _, c := range choices {
			if strings.EqualFold(v, c) {
				return c
			}
		}
		if err != nil {
			// EOF mid-prompt; take the default rather than loop forever.
			return def
		}
		fmt.Fprintf(out, "   (unknown choice %q; pick one of: %s)\n", v, strings.Join(choices, ", "))
	}
	fmt.Fprintf(out, "   (too many invalid attempts; using default %q)\n", def)
	return def
}

// promptYesNo accepts y/yes/n/no (case-insensitive). Empty input
// returns def. EOF returns def.
func promptYesNo(r *bufio.Reader, out io.Writer, label string, def bool) bool {
	defStr := "n"
	if def {
		defStr = "y"
	}
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintf(out, "%s (y/n) [%s]: ", label, defStr)
		line, err := r.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return def
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
		if err != nil {
			return def
		}
		fmt.Fprintln(out, "   (please answer y or n)")
	}
	return def
}

// promptString reads one line. Empty input returns def. EOF returns
// def. The `def` is shown in brackets in the prompt.
func promptString(r *bufio.Reader, out io.Writer, label, def string) string {
	fmt.Fprintf(out, "%s [%s]: ", label, def)
	line, _ := r.ReadString('\n')
	v := strings.TrimSpace(line)
	if v == "" {
		return def
	}
	return v
}

// promptSecret reads one line for a credential. The same prompt
// shape as promptString but rejects empty input twice (the first
// re-prompt is courteous; a second empty answer is an explicit
// abort rather than silently writing an empty key file).
//
// We do not disable terminal echo here — that is the caller's
// responsibility on a real TTY (today's design accepts terminal
// echo for simplicity; future work can wrap term.ReadPassword).
func promptSecret(r *bufio.Reader, out io.Writer, label string) (string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		fmt.Fprintf(out, "%s: ", label)
		line, err := r.ReadString('\n')
		v := strings.TrimSpace(line)
		if v != "" {
			return v, nil
		}
		if err != nil {
			break
		}
		fmt.Fprintln(out, "   (the key cannot be empty)")
	}
	return "", fmt.Errorf("LLM API key was empty; aborting init. Re-run and provide a non-empty key, or skip the advisor")
}

// applyAnswers renders a trollbridge.yaml from the static template
// by substituting the operator's answers. Pure: no I/O. The static
// template's comments survive verbatim.
func applyAnswers(template string, ans initAnswers) string {
	out := template
	out = strings.Replace(out, "proxy:   lo:8080", "proxy:   "+proxyBindFor(ans.topology), 1)
	out = strings.Replace(out, "mode: default-ask", "mode: "+ans.mode, 1)
	if ans.interception {
		out = strings.Replace(out, "  enabled: false\n  ca:", "  enabled: true\n  ca:", 1)
	}
	if ans.llmEnabled {
		out = strings.Replace(out, "  enabled: false\n  provider: anthropic", "  enabled: true\n  provider: "+ans.llmProvider, 1)
		out = strings.Replace(out, "  model:    claude-opus-4-7", "  model:    "+ans.llmModel, 1)
		out = strings.Replace(out, "  api_key_path: /etc/trollbridge/llm.key", "  api_key_path: "+ans.llmKeyPath, 1)
	}
	return out
}

// stdinIsTTY returns true when the supplied reader is *os.File and
// its underlying file descriptor is a terminal. Used to drive the
// auto-fall-back to non-interactive on non-TTY stdin.
//
// Cobra's cmd.InOrStdin() returns os.Stdin in production and a
// strings.Reader / bytes.Buffer in tests; the type assertion makes
// injected test readers always take the non-interactive path.
func stdinIsTTY(in io.Reader) bool {
	f, ok := in.(*os.File)
	if !ok {
		return false
	}
	return isTerminal(int(f.Fd()))
}
