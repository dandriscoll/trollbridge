package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// installStep is one argv tuple to exec, with a human-readable
// description used in the confirmation prompt and progress output.
// Argv assumes the process is already root — no `sudo` prefix.
type installStep struct {
	desc string
	argv []string
}

// stepRunner abstracts the os/exec call so tests can drop in a
// fake. The single method writes the underlying command's stdout
// and stderr to the supplied writer (combined) so the operator
// sees what's happening in real time.
type stepRunner interface {
	run(step installStep, out io.Writer) error
}

type execStepRunner struct{}

func (execStepRunner) run(step installStep, out io.Writer) error {
	cmd := exec.Command(step.argv[0], step.argv[1:]...)
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}

// installStepsFor returns the argv tuples to install the CA into
// the system trust store on a supported platform. Returns nil for
// platforms that --apply does not support (Windows, LinuxUnknown,
// Unknown) — the caller refuses on nil with a platform-specific
// message rather than letting an empty plan fall through.
func installStepsFor(p platform, certPath string) []installStep {
	switch p {
	case platformLinuxDebian, platformLinuxAlpine:
		const dst = "/usr/local/share/ca-certificates/trollbridge-ca.crt"
		return []installStep{
			{desc: "copy CA cert to " + dst, argv: []string{"cp", certPath, dst}},
			{desc: "rebuild system trust store (update-ca-certificates)", argv: []string{"update-ca-certificates"}},
		}
	case platformLinuxFedora:
		const dst = "/etc/pki/ca-trust/source/anchors/trollbridge-ca.crt"
		return []installStep{
			{desc: "copy CA cert to " + dst, argv: []string{"cp", certPath, dst}},
			{desc: "rebuild system trust store (update-ca-trust)", argv: []string{"update-ca-trust"}},
		}
	case platformLinuxArch:
		return []installStep{
			{desc: "install CA cert into trust anchors", argv: []string{"trust", "anchor", "--store", certPath}},
		}
	case platformDarwin:
		return []installStep{
			{
				desc: "add CA cert as trusted root in /Library/Keychains/System.keychain",
				argv: []string{"security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certPath},
			},
		}
	default:
		return nil
	}
}

// applyInstall is the pure logic behind `ca install --apply`. It
// validates the platform, checks privilege, lists steps, prompts
// the operator (unless yes), and dispatches each step to the
// runner. Failure of any step aborts the sequence.
//
// All side-effects flow through arguments — runner for exec, in
// for prompt input, out for all human-facing output, isPrivileged
// for the elevation check — so the function is fully testable
// without touching the live OS.
func applyInstall(
	out io.Writer,
	in io.Reader,
	p platform,
	certPath string,
	yes bool,
	runner stepRunner,
	isPrivileged func() bool,
) error {
	switch p {
	case platformWindows:
		return &runtimeErr{fmt.Errorf("--apply is not supported on Windows; copy the certutil command from `trollbridge ca install` and run it from an elevated (Administrator) shell")}
	case platformLinuxUnknown:
		return &runtimeErr{fmt.Errorf("--apply is not supported on this Linux distribution (auto-detection failed); re-run without --apply to see commands you can copy, or open an issue with /etc/os-release contents to add detection")}
	case platformUnknown:
		return &runtimeErr{fmt.Errorf("--apply is not supported on this OS; re-run without --apply to see the available platforms via --all-platforms")}
	}

	if _, err := os.Stat(certPath); err != nil {
		return &runtimeErr{fmt.Errorf("CA cert not found at %s: %w; run `trollbridge ca init` first", certPath, err)}
	}

	steps := installStepsFor(p, certPath)
	if len(steps) == 0 {
		// Defensive — installStepsFor returns nil for the platforms
		// already rejected above. If we land here, the platform
		// table got out of sync.
		return &runtimeErr{fmt.Errorf("no --apply steps registered for platform %s", p)}
	}

	if !isPrivileged() {
		return &runtimeErr{fmt.Errorf("--apply requires root; rerun as: sudo %s", strings.Join(os.Args, " "))}
	}

	fmt.Fprintf(out, "trollbridge ca install --apply: about to run on %s\n", p.friendly())
	fmt.Fprintf(out, "  cert: %s\n\n", certPath)
	for i, s := range steps {
		fmt.Fprintf(out, "  step %d: %s\n", i+1, s.desc)
		fmt.Fprintf(out, "          $ %s\n", strings.Join(s.argv, " "))
	}
	fmt.Fprintln(out)

	if !yes {
		fmt.Fprint(out, "Proceed? [y/N]: ")
		if !confirmYes(in) {
			return &runtimeErr{fmt.Errorf("aborted by operator")}
		}
	}

	for i, s := range steps {
		fmt.Fprintf(out, "[%d/%d] %s\n", i+1, len(steps), s.desc)
		if err := runner.run(s, out); err != nil {
			return &runtimeErr{fmt.Errorf("step %d (%s) failed: %w", i+1, s.desc, err)}
		}
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "trollbridge ca install --apply: done.")
	return nil
}

// confirmYes reads one line from in and returns true only when the
// trimmed lowercased input is "y" or "yes". Empty input, EOF,
// "n", "no", or any other text returns false. Default-deny is the
// safer affordance for a privileged action.
func confirmYes(in io.Reader) bool {
	r := bufio.NewReader(in)
	line, _ := r.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
