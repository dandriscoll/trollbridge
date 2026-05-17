// Package setupplan is the canonical agentic-onboarding plan for
// trollbridge. It carries the decision tree, the user-facing
// questions, the required-vs-optional structure, and the
// platform-specific notes — as Go data — so a single source feeds
// the JSON plan emitted by `trollbridge setup-plan --json`, the
// markdown view emitted by `--doc`, and the YAML view emitted by
// `--yaml`.
//
// The plan is intentionally *static* (no I/O, no environment
// inspection, no config reads). It describes what an onboarding
// agent should do and ask the user; deciding what to fill in is
// the agent's job. Per-environment dynamic checks live in
// `trollbridge verify`.
//
// The schema is versioned. Renderers carry `PlanVersion` in their
// output so an agent that has cached a plan view can detect drift
// when the binary updates.
package setupplan

// PlanVersion identifies the on-the-wire schema for the rendered
// JSON/YAML plan. Bump on breaking schema changes — adding fields
// is non-breaking, renaming or removing is.
const PlanVersion = "1"

// Plan is the top-level structure an onboarding agent consumes.
// Fields are ordered the way the agent should walk them.
type Plan struct {
	Version             string         `json:"version" yaml:"version"`
	Project             string         `json:"project" yaml:"project"`
	EntryDoc            string         `json:"entry_doc" yaml:"entry_doc"`
	AgenticYAMLTemplate string         `json:"agentic_yaml_template" yaml:"agentic_yaml_template"`
	Summary             string         `json:"summary" yaml:"summary"`
	Goals               []Goal         `json:"goals" yaml:"goals"`
	Questions           []Question     `json:"questions" yaml:"questions"`
	Steps               []Step         `json:"steps" yaml:"steps"`
	PlatformNotes       []PlatformNote `json:"platform_notes" yaml:"platform_notes"`
	Verification        Verification   `json:"verification" yaml:"verification"`
	BackwardCompat      []string       `json:"backward_compat_notes" yaml:"backward_compat_notes"`
}

// Goal is a high-level user objective the agent maps to concrete
// configuration knobs. The agent asks the user which goal(s) fit;
// the `applies_knobs` field tells the agent which YAML decisions
// the goal pre-answers.
type Goal struct {
	ID          string   `json:"id" yaml:"id"`
	Label       string   `json:"label" yaml:"label"`
	Description string   `json:"description" yaml:"description"`
	Knobs       []string `json:"applies_knobs" yaml:"applies_knobs"`
}

// Question is a structured prompt the agent should put to the user.
// Required questions block setup; optional questions only fire if
// the user expresses interest or a `depends_on` resolves to a
// matching answer.
type Question struct {
	ID         string     `json:"id" yaml:"id"`
	Required   bool       `json:"required" yaml:"required"`
	DependsOn  []string   `json:"depends_on,omitempty" yaml:"depends_on,omitempty"`
	Prompt     string     `json:"prompt" yaml:"prompt"`
	Rationale  string     `json:"rationale" yaml:"rationale"`
	Answers    []Answer   `json:"answers,omitempty" yaml:"answers,omitempty"`
	Free       bool       `json:"free_form,omitempty" yaml:"free_form,omitempty"`
	Default    string     `json:"default,omitempty" yaml:"default,omitempty"`
	YAMLPath   string     `json:"yaml_path,omitempty" yaml:"yaml_path,omitempty"`
	SkipWhen   []SkipRule `json:"skip_when,omitempty" yaml:"skip_when,omitempty"`
	Warning    string     `json:"warning,omitempty" yaml:"warning,omitempty"`
	SafeIfSkip string     `json:"safe_if_skip,omitempty" yaml:"safe_if_skip,omitempty"`
}

// Answer is one selectable answer for a structured question.
type Answer struct {
	Value       string `json:"value" yaml:"value"`
	Label       string `json:"label" yaml:"label"`
	Consequence string `json:"consequence" yaml:"consequence"`
}

// SkipRule names a referent question + value the agent can check
// to skip this question. "Skip this question when q.advisor.enabled
// = false."
type SkipRule struct {
	Question string `json:"question" yaml:"question"`
	Value    string `json:"value" yaml:"value"`
}

// Step is one action the agent executes (or asks the user to
// execute) after answers are collected.
type Step struct {
	ID          string   `json:"id" yaml:"id"`
	Title       string   `json:"title" yaml:"title"`
	Description string   `json:"description" yaml:"description"`
	When        string   `json:"when,omitempty" yaml:"when,omitempty"`
	RunBy       string   `json:"run_by" yaml:"run_by"` // "agent" | "user" | "user-elevated"
	Commands    []string `json:"commands" yaml:"commands"`
	Platforms   []string `json:"platforms,omitempty" yaml:"platforms,omitempty"`
}

// PlatformNote carries the OS-specific guidance that does not
// belong inline in a step.
type PlatformNote struct {
	Platform string   `json:"platform" yaml:"platform"`
	Notes    []string `json:"notes" yaml:"notes"`
}

// Verification names the commands the agent runs to confirm setup
// is complete, and the contract for the responses.
type Verification struct {
	Command         string   `json:"command" yaml:"command"`
	JSON            bool     `json:"json" yaml:"json"`
	Confirms        []string `json:"confirms" yaml:"confirms"`
	ManualFollowups []string `json:"manual_followups,omitempty" yaml:"manual_followups,omitempty"`
}

// Build returns the canonical plan instance. Builder rather than a
// `var` so test mutations cannot leak across callers.
func Build() Plan {
	return Plan{
		Version:             PlanVersion,
		Project:             "trollbridge",
		EntryDoc:            "SETUP-AGENT.md",
		AgenticYAMLTemplate: "config.agentic.yaml",
		Summary: "trollbridge is an HTTP/HTTPS forward proxy that " +
			"gates an agent's network egress against a deterministic " +
			"policy, with an optional LLM advisor for ambiguous " +
			"requests. The plan below walks an onboarding agent " +
			"through install, configure, run, and verify.",
		Goals:          goals(),
		Questions:      questions(),
		Steps:          steps(),
		PlatformNotes:  platformNotes(),
		Verification:   verification(),
		BackwardCompat: backwardCompat(),
	}
}

func goals() []Goal {
	return []Goal{
		{
			ID:    "block-exfiltration",
			Label: "Block credential exfiltration / least-privileged egress",
			Description: "User wants the agent's egress restricted to a " +
				"named allowlist; everything else blocked. Strong-isolation " +
				"intent. Implies default-deny, curated allow list, " +
				"hardened deny list (metadata services, pastebins).",
			Knobs: []string{"mode=default-deny", "lists.allow=curated", "lists.deny=metadata+exfil"},
		},
		{
			ID:    "review-new-destinations",
			Label: "Review every new destination",
			Description: "User wants unmatched requests held for human " +
				"or LLM-advisor review. Implies default-ask plus advisor " +
				"on for tractability — otherwise every novel request " +
				"blocks until a human approves.",
			Knobs: []string{"mode=default-ask", "llm.enabled=true"},
		},
		{
			ID:    "audit-but-not-block",
			Label: "Audit but don't block",
			Description: "User wants a forensic record without breaking " +
				"the agent's network access. Implies default-allow + " +
				"deny list of known-bad destinations. Audit log is the " +
				"primary control.",
			Knobs: []string{"mode=default-allow", "lists.deny=metadata+exfil"},
		},
		{
			ID:    "scoped-to-ci-or-package-mirrors",
			Label: "Let agent fetch from specific package mirrors only",
			Description: "User has named hosts (npm, pypi, GitHub) and " +
				"wants nothing else. Implies default-deny with a small " +
				"allow list; no advisor needed.",
			Knobs: []string{"mode=default-deny", "lists.allow=named-mirrors", "llm.enabled=false"},
		},
		{
			ID:    "different-agents-different-rules",
			Label: "Different agents have different permissions",
			Description: "User has multiple agents (mTLS / bearer / source IP) " +
				"each with its own policy. Implies identities: + " +
				"structured rules under policy.include with match.identity. " +
				"Advanced; defer until base setup works.",
			Knobs: []string{"identities=defined", "policy.include=structured-rules"},
		},
	}
}

func questions() []Question {
	return []Question{
		{
			ID:        "q.install_mode",
			Required:  true,
			Prompt:    "Will trollbridge run as YOU (user mode) or as a system service (daemon mode)?",
			Rationale: "Install mode picks where files live and which user the daemon runs as. It is the load-bearing axis — every later default branches off it. Daemon-mode is not supported on Windows.",
			Default:   "user",
			YAMLPath:  "<install-mode>",
			Answers: []Answer{
				{Value: "user", Label: "user — runs as the operator; files anchored at the init directory; no sudo at any step.", Consequence: "Simplest. CA files and audit log live next to trollbridge.yaml. Works on Linux, macOS, and Windows."},
				{Value: "daemon", Label: "daemon — runs as the `trollbridge` system user; files under /etc/trollbridge/ and /var/log/trollbridge/; setup uses sudo.", Consequence: "Hardened. NOT supported on Windows. The daemon never runs as root."},
			},
		},
		{
			ID:        "q.topology",
			Required:  true,
			Prompt:    "Where does the agent run relative to the proxy?",
			Rationale: "Topology decides the proxy's bind address. local keeps it on loopback; local-vm and remote require binding on all interfaces so the consumer host can reach it.",
			Default:   "local",
			YAMLPath:  "proxy",
			Answers: []Answer{
				{Value: "local", Label: "local — agent on the same host as the proxy.", Consequence: "Proxy binds to lo:8080 (loopback). No firewall changes."},
				{Value: "local-vm", Label: "local-vm — agent in a VM on this host.", Consequence: "Proxy binds to all:8080. Make sure host firewall permits the VM bridge."},
				{Value: "remote", Label: "remote — agent on a different machine.", Consequence: "Proxy binds to all:8080. Open the port to the consumer's network."},
			},
		},
		{
			ID:        "q.policy_mode",
			Required:  true,
			Prompt:    "What posture should the proxy enforce by default?",
			Rationale: "Choose by the user's stated goal: default-deny for exfiltration control; default-ask for review-every-new; default-allow for audit-only.",
			Default:   "default-deny",
			YAMLPath:  "mode",
			Answers: []Answer{
				{Value: "default-deny", Label: "default-deny — only listed hosts forward; everything else blocked (HTTP 470).", Consequence: "Safest. The agent's first call to an unlisted host is refused."},
				{Value: "default-ask", Label: "default-ask — unmatched requests are held for advisor / operator approval.", Consequence: "Most flexible. Requires the LLM advisor on (next question) for tractability."},
				{Value: "default-allow", Label: "default-allow — only deny rules block; audit log captures the rest.", Consequence: "Lowest friction. Audit-log review is the primary control."},
			},
		},
		{
			ID:        "q.interception",
			Required:  true,
			Prompt:    "Should trollbridge intercept TLS (decrypt HTTPS to see paths/bodies)?",
			Rationale: "Without interception, the proxy sees only host:port for HTTPS — path, method, header, and body rules cannot fire. With interception, the agent's clients must trust trollbridge's CA certificate.",
			Default:   "false",
			YAMLPath:  "interception.enabled",
			Answers: []Answer{
				{Value: "false", Label: "off — HTTPS rules match host:port only. No CA install required.", Consequence: "Lowest setup cost. Good first session."},
				{Value: "true", Label: "on — full HTTPS inspection; requires installing trollbridge-ca.crt into the client trust store.", Consequence: "Requires CA install step on every consumer host (root/Administrator). Plan calls it out as a follow-up step."},
			},
			Warning: "Turning interception on is invasive — the CA must be installed into every consumer process's trust store (system store, Node, Python, Java, etc.). Default off unless the user accepts the cost.",
		},
		{
			ID:        "q.advisor.enabled",
			Required:  true,
			Prompt:    "Enable the LLM advisor for ambiguous requests?",
			Rationale: "The advisor fires on `ask_llm` rules and in default-ask mode. It cannot elevate above the deterministic policy (the policy is always load-bearing).",
			Default:   "false",
			YAMLPath:  "llm.enabled",
			Answers: []Answer{
				{Value: "true", Label: "on — advisor classifies ambiguous requests.", Consequence: "Required for default-ask to be practical; optional otherwise."},
				{Value: "false", Label: "off — the deterministic policy is the only decider.", Consequence: "Simpler; no API key needed."},
			},
			SafeIfSkip: "false (no advisor) is safe whenever mode != default-ask.",
		},
		{
			ID:        "q.advisor.provider",
			Required:  true,
			DependsOn: []string{"q.advisor.enabled=true"},
			Prompt:    "Which LLM provider should the advisor use?",
			Rationale: "Provider selects the auth header and wire shape. Anthropic uses x-api-key + Messages API. Azure OpenAI (aoai) uses api-key + chat-completions/Responses API.",
			Default:   "anthropic",
			YAMLPath:  "llm.provider",
			Answers: []Answer{
				{Value: "anthropic", Label: "Anthropic Claude.", Consequence: "Default endpoint https://api.anthropic.com/v1/messages. See ANTHROPIC-LLM-SETUP-AGENT.md."},
				{Value: "aoai", Label: "Azure OpenAI.", Consequence: "Endpoint must be the deployment-scoped chat-completions URL. See AZURE-OPENAI-LLM-SETUP-AGENT.md."},
			},
		},
		{
			ID:        "q.advisor.model",
			Required:  true,
			DependsOn: []string{"q.advisor.enabled=true"},
			Free:      true,
			Prompt:    "Which model / deployment name should the advisor call?",
			Rationale: "For anthropic this is the model id (e.g. claude-opus-4-7). For aoai this is the deployment name in the URL.",
			Default:   "claude-opus-4-7",
			YAMLPath:  "llm.model",
		},
		{
			ID:        "q.advisor.endpoint",
			Required:  true,
			DependsOn: []string{"q.advisor.enabled=true", "q.advisor.provider=aoai"},
			Free:      true,
			Prompt:    "What is the advisor endpoint URL?",
			Rationale: "Anthropic has a sensible default and may be skipped. aoai REQUIRES the deployment-scoped URL with api-version query string.",
			YAMLPath:  "llm.endpoint",
		},
		{
			ID:        "q.advisor.api_key",
			Required:  true,
			DependsOn: []string{"q.advisor.enabled=true"},
			Free:      true,
			Prompt:    "Provide the advisor's API key (will be written to a file with mode 0600 — NEVER inline in trollbridge.yaml).",
			Rationale: "trollbridge.yaml stores only the *path* (llm.api_key_path). The key goes into a separate file the operator owns.",
			YAMLPath:  "llm.api_key_path",
			Warning:   "NEVER put the API key inline in trollbridge.yaml. The yaml stores the path; the key lives in a chmod-600 file.",
		},
		{
			ID:        "q.audit_path",
			Required:  false,
			Prompt:    "Where should the JSONL audit log live?",
			Rationale: "Default is the init directory in user-mode, /var/log/trollbridge/audit.jsonl in daemon-mode. Override only if the user has a specific log retention setup.",
			YAMLPath:  "logging.audit_path",
			SafeIfSkip: "the install-mode default is fine for most users.",
		},
	}
}

func steps() []Step {
	return []Step{
		{
			ID:          "s.install.linux-macos",
			Title:       "Install the binary (Linux / macOS)",
			Description: "Fetches the latest release tarball, verifies SHA256, installs to ~/.local/bin.",
			RunBy:       "user",
			Platforms:   []string{"linux", "darwin"},
			Commands: []string{
				"curl -fsSL https://trollbridge.dev/install.sh | bash",
				"trollbridge version",
			},
		},
		{
			ID:          "s.install.windows",
			Title:       "Install the binary (Windows)",
			Description: "PowerShell snippet: fetches trollbridge.exe from the latest release and drops it on PATH. SHA256 verification is the operator's responsibility — surface the checksum URL to the user.",
			RunBy:       "user",
			Platforms:   []string{"windows"},
			Commands: []string{
				"# In PowerShell:",
				"$Ver = (Invoke-RestMethod https://api.github.com/repos/dandriscoll/trollbridge/releases/latest).tag_name",
				"$Url = \"https://github.com/dandriscoll/trollbridge/releases/download/$Ver/trollbridge_${Ver}_windows_amd64.exe\"",
				"New-Item -ItemType Directory -Force -Path $env:LOCALAPPDATA\\Programs\\trollbridge | Out-Null",
				"Invoke-WebRequest -Uri $Url -OutFile $env:LOCALAPPDATA\\Programs\\trollbridge\\trollbridge.exe",
				"# Append to PATH for this session (persist via System Properties → Environment Variables):",
				"$env:Path = \"$env:LOCALAPPDATA\\Programs\\trollbridge;$env:Path\"",
				"trollbridge version",
			},
		},
		{
			ID:          "s.collect-answers",
			Title:       "Ask the user the required questions",
			Description: "Walk the Question[] list. Skip any q.required=false unless relevant to the user's stated goal. For q.depends_on, only ask after the dependency resolved to a matching value. Collect answers into a file matching the schema in config.agentic.yaml's `# answers-file` header.",
			RunBy:       "agent",
		},
		{
			ID:          "s.write-answers-file",
			Title:       "Write the answers file",
			Description: "Serialize the collected answers as YAML. Schema header: `# trollbridge-init-answers v1`. Sample shape ships in config.agentic.yaml.",
			RunBy:       "agent",
			Commands: []string{
				"# Write the answers file (the agent does this; example shape):",
				"cat > trollbridge-answers.yaml <<'YAML'",
				"# trollbridge-init-answers v1",
				"install_mode: user",
				"topology: local",
				"mode: default-deny",
				"interception: false",
				"llm:",
				"  enabled: false",
				"YAML",
			},
		},
		{
			ID:          "s.render-yaml",
			Title:       "Render trollbridge.yaml from the answers",
			Description: "Calls trollbridge init non-interactively with the answers file. Produces ./trollbridge.yaml.",
			RunBy:       "agent",
			Commands: []string{
				"trollbridge init --answers ./trollbridge-answers.yaml",
			},
		},
		{
			ID:          "s.ca-generate",
			Title:       "Generate the CA (only if interception=on)",
			Description: "`trollbridge ca init` writes the CA cert and key. user-mode writes to the init dir; daemon-mode writes to /etc/trollbridge/ (root required).",
			RunBy:       "user-elevated",
			When:        "interception=true",
			Commands: []string{
				"# user-mode:",
				"trollbridge ca init",
				"# daemon-mode (Linux only):",
				"sudo -u trollbridge trollbridge ca init",
			},
		},
		{
			ID:          "s.ca-install",
			Title:       "Install the CA on each consumer host (only if interception=on)",
			Description: "Each host whose apps will route through the proxy needs the CA in its trust store. The agent cannot do this without root/Administrator — surface the exact command for the user.",
			RunBy:       "user-elevated",
			When:        "interception=true",
			Commands: []string{
				"# Linux/macOS (after copying trollbridge-ca.crt to the consumer):",
				"sudo trollbridge ca install --apply",
				"# Windows (Administrator PowerShell):",
				"certutil -addstore -f \"Root\" trollbridge-ca.crt",
			},
		},
		{
			ID:          "s.llm-key",
			Title:       "Write the LLM API key file (only if advisor=on, daemon-mode only)",
			Description: "user-mode init wrote the key file inline from the answer. daemon-mode requires the operator to write it as the trollbridge user — the agent cannot.",
			RunBy:       "user-elevated",
			When:        "advisor.enabled=true AND install_mode=daemon",
			Commands: []string{
				"# Paste key, then Ctrl-D:",
				"sudo -u trollbridge install -m 600 /dev/stdin /etc/trollbridge/llm.key",
			},
		},
		{
			ID:          "s.validate",
			Title:       "Validate the configuration",
			Description: "Strict YAML parse, rule load, list parse. Exit 0 = clean, exit 1 = error message names the offending field.",
			RunBy:       "agent",
			Commands: []string{
				"trollbridge validate --json -c ./trollbridge.yaml",
			},
		},
		{
			ID:          "s.doctor",
			Title:       "Run doctor (deeper checks; calls the LLM if enabled)",
			Description: "Loads everything, plus performs a synthetic LLM classification call if advisor is on. Use --check-llm to verify the wiring before flipping enabled: true.",
			RunBy:       "agent",
			Commands: []string{
				"trollbridge doctor -c ./trollbridge.yaml",
			},
		},
		{
			ID:          "s.start",
			Title:       "Start the proxy",
			Description: "Runs in the foreground (block-and-serve). Pass --no-console for non-TTY environments. user-mode runs as the operator; daemon-mode runs under systemd (see packaging/systemd/).",
			RunBy:       "user",
			Commands: []string{
				"# Foreground (interactive):",
				"trollbridge run -c ./trollbridge.yaml",
				"# Or, daemon-mode under systemd:",
				"sudo systemctl start trollbridge",
			},
		},
		{
			ID:          "s.verify",
			Title:       "Verify the running system",
			Description: "Single command. Parses the config, probes the proxy's bind address, fetches /setup through the proxy. Emits structured JSON naming what works and what needs manual action.",
			RunBy:       "agent",
			Commands: []string{
				"trollbridge verify --json -c ./trollbridge.yaml",
			},
		},
	}
}

func platformNotes() []PlatformNote {
	return []PlatformNote{
		{
			Platform: "linux",
			Notes: []string{
				"Both user and daemon install modes are supported.",
				"`trollbridge ca install --apply` automates trust-store install on Debian/Ubuntu, RHEL/Fedora, Alpine, and Arch.",
				"Daemon-mode requires the systemd unit at packaging/systemd/trollbridge.service.",
				"The firewall is part of the security perimeter — see packaging/firewall/iptables.sh or nftables.sh.",
			},
		},
		{
			Platform: "darwin",
			Notes: []string{
				"Both user and daemon install modes work; daemon-mode does not ship a launchd unit (use systemctl-style supervision via brew services or write your own plist).",
				"`trollbridge ca install --apply` uses `security add-trusted-cert` against the system keychain (requires sudo).",
				"Application-runtime trust (Java cacerts, Node NODE_EXTRA_CA_CERTS) still needs per-runtime configuration even after the keychain install.",
			},
		},
		{
			Platform: "windows",
			Notes: []string{
				"Only user-mode is supported. Daemon-mode is refused with a clear error (no Windows-service integration, no NTFS ACL on CA keys yet — tracked).",
				"Install via direct .exe download from the GitHub release; the curl|sh installer is Linux/macOS only.",
				"CA install: `trollbridge ca install` prints the certutil command; the operator runs it from an elevated PowerShell (--apply is not automated on Windows).",
				"Paths render under %ProgramData% by default; the agent should NOT propose /etc/trollbridge/ paths on Windows.",
			},
		},
	}
}

func verification() Verification {
	return Verification{
		Command: "trollbridge verify --json -c <config>",
		JSON:    true,
		Confirms: []string{
			"config_parses: the YAML loads cleanly through the strict decoder.",
			"proxy_reachable: a TCP dial against the configured bind address succeeds.",
			"self_describe_reachable: a GET through the proxy to http://config.trollbridge.dev/setup returns 200.",
			"policy_mode: the proxy is enforcing the configured mode (default-deny / default-allow / default-ask).",
			"interception_state: ON when configured, with CA cert reachable at the configured path.",
			"advisor_state: ON+OK when llm.enabled and a synthetic classification call succeeds; otherwise OFF.",
		},
		ManualFollowups: []string{
			"If interception=on but the CA is NOT installed on the consumer host, verify reports a gap. The agent surfaces the exact `ca install` command to the user.",
			"If the consumer host is different from the proxy host, copying trollbridge-ca.crt to the consumer is a user step the agent cannot automate.",
			"If the user has not configured the consumer's HTTP_PROXY env vars, the proxy will sit idle. The agent surfaces the env-var snippet from `trollbridge env`.",
		},
	}
}

func backwardCompat() []string {
	return []string{
		"Existing `curl -fsSL https://trollbridge.dev/install.sh | sh` works unchanged.",
		"Existing `trollbridge init` (interactive, on a TTY) works unchanged. The new --answers flag is opt-in.",
		"Existing `trollbridge quickstart` works unchanged.",
		"Existing trollbridge.yaml configs continue to load; no schema changes.",
		"The four day-to-day commands (logs tail, decisions, approve, deny) are unchanged.",
	}
}
