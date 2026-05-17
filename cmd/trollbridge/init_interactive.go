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

// readPassword wraps term.ReadPassword for the same reason as
// isTerminal: tests that emulate a TTY via os.Pipe() cannot run the
// real termios syscalls (a pipe fd is not a terminal), so they stub
// this var to feed scripted bytes through the same code path.
var readPassword = func(fd int) ([]byte, error) { return term.ReadPassword(fd) }

// initAnswers carries the result of the interactive `init` flow.
// `applyAnswers` consumes this to render the final YAML; `init.go`
// consumes it to decide whether to chain into ca.Init / write the
// LLM key file.
//
// Topology presets are framed by where the agent runs relative to
// the proxy: `local` (same host, shares loopback), `local-vm` (a VM
// on the same host, reaches the proxy across a bridge), `remote`
// (a different machine).
type initAnswers struct {
	installMode  string // "user" | "daemon" — see the install-mode question below
	topology     string // "local" | "local-vm" | "remote"
	mode         string // "default-deny" | "default-allow" | "default-ask"  (policy posture)
	interception bool
	caCertPath   string // absolute path to the CA cert when interception=on; empty otherwise
	caKeyPath    string // absolute path to the CA key when interception=on; empty otherwise
	auditPath    string // absolute path to the audit log
	llmEnabled   bool
	llmProvider  string // "anthropic" | "aoai" | <other string>
	llmModel     string
	llmEndpoint  string // operator-supplied URL when provider != "anthropic"; empty preserves the template default
	llmKeyPath   string // absolute path to the LLM API key file
	llmKey       string // present only if llmEnabled AND user-mode; init writes the file inline
}

// proxyBindFor maps a topology choice to the proxy bind string.
// `local` shares the host's loopback; `local-vm` and `remote` reach
// the proxy across a routable interface, so the daemon must bind on
// all interfaces (operators can tighten to a specific bridge IP by
// editing the rendered yaml).
func proxyBindFor(topology string) string {
	switch topology {
	case "local-vm", "remote":
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
		installMode: "user",
		topology:    "local",
		mode:        "default-ask",
		llmProvider: "anthropic",
		llmModel:    "claude-opus-4-7",
	}

	fmt.Fprintln(out, "trollbridge init: guided setup. Press return to accept defaults shown in [brackets].")
	fmt.Fprintln(out)

	// 1. Install mode — the load-bearing axis. Picks where files
	// live and which user the daemon will run as. Asked first
	// because every later answer's defaults depend on it.
	fmt.Fprintln(out, "1) How will trollbridge be installed?")
	fmt.Fprintln(out, "   user    — for me, this user. Files under the current directory; runtime as you.")
	fmt.Fprintln(out, "             No sudo needed at any step.")
	fmt.Fprintln(out, "   daemon  — system service. Files under /etc/trollbridge/ and /var/log/trollbridge/;")
	fmt.Fprintln(out, "             runtime as a `trollbridge` system user (not root). Setup uses sudo.")
	ans.installMode = promptChoice(r, out,
		"   install mode",
		[]string{"user", "daemon"},
		ans.installMode,
	)
	fmt.Fprintln(out)

	// 2. Topology — keyed on where the agent runs relative to the proxy.
	fmt.Fprintln(out, "2) Where will the agent run?")
	fmt.Fprintln(out, "   local     — agent on this host (shares loopback with the proxy).")
	fmt.Fprintln(out, "   local-vm  — agent in a VM on this host (reaches the proxy via a bridge).")
	fmt.Fprintln(out, "   remote    — agent on a different machine.")
	ans.topology = promptChoice(r, out,
		"   topology",
		[]string{"local", "local-vm", "remote"},
		ans.topology,
	)
	fmt.Fprintf(out, "   → proxy bind: %s\n\n", proxyBindFor(ans.topology))

	// 3. Policy posture
	fmt.Fprintln(out, "3) What policy posture should the proxy enforce?")
	fmt.Fprintln(out, "   default-deny  — only listed hosts forward; everything else is blocked.")
	fmt.Fprintln(out, "   default-allow — only blocklisted hosts are denied; audit log captures the rest.")
	fmt.Fprintln(out, "   default-ask   — unmatched requests are held for advisor or operator approval.")
	ans.mode = promptChoice(r, out,
		"   mode",
		[]string{"default-deny", "default-allow", "default-ask"},
		ans.mode,
	)
	fmt.Fprintln(out)

	// 4. TLS interception
	fmt.Fprintln(out, "4) Enable TLS interception? (lets trollbridge see HTTPS request paths/bodies; requires installing a CA in the client trust store.)")
	ans.interception = promptYesNo(r, out, "   interception", false)
	fmt.Fprintln(out)

	// 5. LLM advisor
	fmt.Fprintln(out, "5) Enable the LLM advisor? (classifies ambiguous requests when policy says ask_llm.)")
	ans.llmEnabled = promptYesNo(r, out, "   advisor", false)
	if ans.llmEnabled {
		ans.llmProvider = promptChoice(r, out,
			"   provider",
			[]string{"anthropic", "aoai", "other"},
			ans.llmProvider,
		)
		// Provider-aware model default: the struct-init value above is
		// the anthropic default. Azure OpenAI does not serve Claude
		// models, so suggest a sensible Azure deployment placeholder
		// instead (#131); `other` has no useful default.
		switch ans.llmProvider {
		case "aoai":
			ans.llmModel = "gpt-4o-mini"
		case "other":
			ans.llmModel = ""
		}
		ans.llmModel = promptString(r, out, "   model", ans.llmModel)
		// Endpoint: anthropic uses the template default; aoai/other
		// have no useful default and must be supplied.
		if ans.llmProvider != "anthropic" {
			ep, err := promptRequiredString(r, out, "   endpoint URL")
			if err != nil {
				return ans, err
			}
			ans.llmEndpoint = ep
		}
		// In user-mode init writes the key file inline (no privilege
		// needed). In daemon-mode the key file lives at /etc/
		// trollbridge/llm.key and the operator writes it themselves
		// (next-steps document the recipe) — `init` itself runs at no
		// privilege, regardless of mode.
		if ans.installMode == "user" {
			key, err := promptSecret(in, r, out, "   API key (paste; will not be echoed back)")
			if err != nil {
				return ans, err
			}
			ans.llmKey = key
		} else {
			fmt.Fprintln(out, "   → daemon-mode: write the API key separately on the proxy host as the")
			fmt.Fprintln(out, "     `trollbridge` user. See the next-steps for the exact recipe.")
		}
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

// promptRequiredString reads one line and rejects empty input. Two
// empty answers in a row return an error rather than looping forever
// — same shape as promptSecret, used for fields that have no useful
// default (e.g., the LLM endpoint URL for non-anthropic providers).
func promptRequiredString(r *bufio.Reader, out io.Writer, label string) (string, error) {
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
		fmt.Fprintf(out, "   (%s cannot be empty)\n", strings.TrimSpace(label))
	}
	return "", fmt.Errorf("%s was empty; aborting init", strings.TrimSpace(label))
}

// promptSecret reads one line for a credential. The same prompt
// shape as promptString but rejects empty input twice (the first
// re-prompt is courteous; a second empty answer is an explicit
// abort rather than silently writing an empty key file).
//
// On a real TTY, terminal echo is suppressed via term.ReadPassword
// so the operator's keystrokes do not appear on screen — the prompt
// label promises that property and the implementation must deliver
// it. On non-TTY input (piped, redirected) there is no terminal to
// echo to; the existing bufio.Reader path runs, preserving any
// already-buffered data the parent reader holds.
func promptSecret(in io.Reader, r *bufio.Reader, out io.Writer, label string) (string, error) {
	tty := false
	var fd int
	if f, ok := in.(*os.File); ok {
		fd = int(f.Fd())
		tty = isTerminal(fd)
	}
	for attempt := 0; attempt < 2; attempt++ {
		fmt.Fprintf(out, "%s: ", label)
		var v string
		if tty {
			b, err := readPassword(fd)
			// term.ReadPassword swallows the operator's newline; print
			// one so subsequent output starts on a fresh line.
			fmt.Fprintln(out)
			if err != nil {
				return "", fmt.Errorf("read API key: %w", err)
			}
			v = strings.TrimSpace(string(b))
		} else {
			line, err := r.ReadString('\n')
			v = strings.TrimSpace(line)
			if v == "" && err != nil {
				break
			}
		}
		if v != "" {
			return v, nil
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
	if ans.caCertPath != "" {
		out = strings.Replace(out, "    cert_path: "+DefaultCACertPath, "    cert_path: "+ans.caCertPath, 1)
	}
	if ans.caKeyPath != "" {
		out = strings.Replace(out, "    key_path:  "+DefaultCAKeyPath, "    key_path:  "+ans.caKeyPath, 1)
	}
	if ans.auditPath != "" {
		out = strings.Replace(out, "  audit_path:        "+DefaultDaemonAuditPath, "  audit_path:        "+ans.auditPath, 1)
	}
	if ans.llmEnabled {
		out = strings.Replace(out, "  enabled: false\n  provider: anthropic", "  enabled: true\n  provider: "+ans.llmProvider, 1)
		out = strings.Replace(out, "  model:    claude-opus-4-7", "  model:    "+ans.llmModel, 1)
		out = strings.Replace(out, "  api_key_path: "+DefaultDaemonLLMKeyPath, "  api_key_path: "+ans.llmKeyPath, 1)
		if ans.llmEndpoint != "" {
			out = strings.Replace(out, "  endpoint: https://api.anthropic.com/v1/messages", "  endpoint: "+ans.llmEndpoint, 1)
		}
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
