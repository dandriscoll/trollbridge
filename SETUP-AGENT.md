# SETUP-AGENT.md — single entry for agentic trollbridge onboarding

> **Audience:** an LLM-driven onboarding agent (Claude Code, Cursor,
> Aider, OpenAI Codex, or similar) that has been asked by a user to
> install and configure **trollbridge**, an HTTP/HTTPS policy proxy
> for LLM agents.
>
> **You only need this one file.** Hand this URL/path to your agent
> and the agent walks the user through install → configure → run →
> verify on Linux, macOS, or Windows.

If you are a different kind of agent, you want a different file:

- An agent **pointing your own egress at a running trollbridge** —
  read [`CLIENT-SETUP-AGENT.md`](CLIENT-SETUP-AGENT.md).
- An agent whose **own runtime egress goes through trollbridge** —
  read [`PROXIED-AGENT.md`](PROXIED-AGENT.md).
- A coding agent working **on the trollbridge codebase** —
  read [`AGENTS.md`](AGENTS.md).

## What "agentic onboarding" means here

An onboarding LLM agent receives this single document and drives
the entire setup end-to-end:

1. Understands the available setup paths from this document and
   from [`config.agentic.yaml`](config.agentic.yaml).
2. Identifies the user's high-level goals (block exfiltration?
   review every new destination? audit only?).
3. Asks the user the *minimum* set of questions needed for those
   goals.
4. Skips irrelevant optional questions; uses safe defaults.
5. Writes an answers file matching the schema in
   [`config.agentic.yaml`](config.agentic.yaml).
6. Calls `trollbridge init --answers <file>` to render
   `trollbridge.yaml`.
7. Runs the platform-appropriate install / CA / start steps.
8. Runs `trollbridge verify --json` and parses the result to
   decide done-vs-not-done.
9. Reports completion plus any remaining manual steps to the user.

## The two surfaces you read

| Surface | Format | When you read it |
|---|---|---|
| **`SETUP-AGENT.md`** (this file) | Markdown | First — orients you to the flow. |
| **`config.agentic.yaml`** | Annotated YAML | The decision tree as YAML comments. Use it to drive your questions. |
| `trollbridge setup-plan --json` | JSON | Same plan as data. Use it if you prefer programmatic input over reading comments. |
| `trollbridge setup-plan --doc` | Markdown | Same content as the JSON, formatted for prose-driven agents. |

The YAML template, the JSON plan, and the markdown view come from
**one source** (`internal/setupplan/plan.go`). They cannot drift;
the test suite asserts they match. You can use any of them.

## Quick reference: the agentic flow

### 0. Install the binary

`trollbridge` is a single static Go binary. Install it once per
host.

**Linux / macOS:**
```sh
curl -fsSL https://trollbridge.dev/install.sh | bash
trollbridge version
```

**Windows (PowerShell):**
```powershell
$Ver = (Invoke-RestMethod https://api.github.com/repos/dandriscoll/trollbridge/releases/latest).tag_name
$Url = "https://github.com/dandriscoll/trollbridge/releases/download/$Ver/trollbridge_${Ver}_windows_amd64.exe"
New-Item -ItemType Directory -Force -Path $env:LOCALAPPDATA\Programs\trollbridge | Out-Null
Invoke-WebRequest -Uri $Url -OutFile $env:LOCALAPPDATA\Programs\trollbridge\trollbridge.exe
$env:Path = "$env:LOCALAPPDATA\Programs\trollbridge;$env:Path"
trollbridge version
```

### 1. Read the plan

```sh
trollbridge setup-plan --doc      # if you want markdown
trollbridge setup-plan --json     # if you want data
```

Or open [`config.agentic.yaml`](config.agentic.yaml) directly —
the YAML comments carry the same decision tree.

### 2. Ask the user the goal-level question first

Pick ONE primary goal from this list. The user's choice
pre-answers most of the configuration knobs:

| Goal | Maps to |
|---|---|
| Block exfiltration / least-privileged egress | `mode: default-deny`, curated `lists.allow`, hardened `lists.deny` |
| Review every new destination | `mode: default-ask` + `llm.enabled: true` |
| Audit but don't block | `mode: default-allow`, hardened `lists.deny` |
| Let agent fetch from specific package mirrors only | `mode: default-deny`, `lists.allow` = named mirrors |
| Different agents have different permissions | `identities:` + structured rules (advanced; defer) |

### 3. Ask the REQUIRED follow-ups, in this order

The order is load-bearing — earlier answers change later defaults.

1. **`install_mode`** — `user` (this user, no sudo) or `daemon`
   (system service, Linux only). Default `user`.
2. **`topology`** — `local` / `local-vm` / `remote`. Default
   `local`. Picks the proxy's bind address.
3. **`interception`** — `false` (HTTPS by host:port only) or
   `true` (full TLS interception; requires CA install on every
   consumer). Default `false`; turn on only if the user accepts
   the cost.
4. **LLM advisor on?** Default `false`. If `true`, ask provider /
   model / endpoint / API key. (See
   [`ANTHROPIC-LLM-SETUP-AGENT.md`](ANTHROPIC-LLM-SETUP-AGENT.md)
   and [`AZURE-OPENAI-LLM-SETUP-AGENT.md`](AZURE-OPENAI-LLM-SETUP-AGENT.md)
   for provider-specific guidance.)

Skip every other question unless the user volunteers a constraint
that requires it.

### 4. Write the answers file

Format: YAML, schema header `# trollbridge-init-answers v1`. The
canonical sample is at the top of
[`config.agentic.yaml`](config.agentic.yaml).

Minimal example for the "block exfiltration, local, no
interception, no advisor" path:

```yaml
# trollbridge-init-answers v1
install_mode: user
topology: local
mode: default-deny
interception: false
```

### 5. Render `trollbridge.yaml`

```sh
trollbridge init --answers ./trollbridge-answers.yaml
```

The CLI runs the same `applyAnswers` rendering the interactive
flow uses; the answers file is just a non-TTY input channel.
Strict YAML decoding rejects unknown keys (so a typo surfaces at
load time, not silently).

### 6. Generate the CA (only if interception=true)

```sh
trollbridge ca init                                # user-mode
# or, daemon-mode (Linux only):
sudo -u trollbridge trollbridge ca init
```

### 7. Install the CA on each consumer host (only if interception=true)

The agent cannot do this — surface the exact command to the user.

```sh
# Linux/macOS:
sudo trollbridge ca install --apply
# Windows (Administrator PowerShell):
certutil -addstore -f "Root" trollbridge-ca.crt
```

### 8. Start the proxy

```sh
trollbridge run -c ./trollbridge.yaml
# or, daemon-mode under systemd:
sudo systemctl start trollbridge
```

`run` prints a startup banner naming the listen address. In a
non-TTY environment (CI, container without a tty), pass
`--no-console` to suppress the operator UI.

### 9. Verify — this is your done-check

```sh
trollbridge verify --json -c ./trollbridge.yaml
```

The JSON has stable fields. Read `ok` first:

```json
{
  "ok": true,
  "config_parses": true,
  "mode": "default-deny",
  "proxy_addr": "127.0.0.1:8080",
  "proxy_reachable": true,
  "self_describe_reachable": true,
  "interception": { "enabled": false, "ok": true, "detail": "..." },
  "advisor":      { "enabled": false, "ok": true, "detail": "..." },
  "gaps": [],
  "next_actions": [],
  "confirmations": ["..."]
}
```

If `ok: false`, read `gaps[]`. Each gap has `id`, `what`, and
`next_action` — surface the `next_action` to the user verbatim
for any gap where `blocks_ok: true`.

### 10. Report completion

Tell the user:

1. **Mode and topology** chosen.
2. **Where trollbridge is running** (the `proxy_addr` from
   verify).
3. **Whether interception is on** and, if so, whether the CA was
   installed on the consumer hosts they need.
4. **Whether the advisor is on** and which provider/model.
5. **Where the audit log lives.**
6. **The four day-to-day commands**: `trollbridge logs tail
   --follow`, `trollbridge decisions --since 1h`, `trollbridge
   approve <id>`, `trollbridge deny <id>`.
7. **Any remaining manual steps** from `verify.gaps[]`.

## Decision tree at a glance

```
START
  ↓
[Q1] install_mode? ──────────── user (default; required) | daemon (Linux only)
  ↓
[Q2] topology? ──────────────── local (default) | local-vm | remote
  ↓
[Q3] policy mode? ──────────── default-deny (default) | default-ask | default-allow
  ↓
[Q4] interception? ──────────── false (default) | true
                                  ↓ true
                                [Q4a] CA-install plan: name consumer hosts
  ↓
[Q5] advisor? ──────────────── false (default) | true
                                  ↓ true
                                [Q5a] provider (anthropic/aoai)
                                [Q5b] model
                                [Q5c] endpoint (aoai only)
                                [Q5d] API key (write to file, NEVER yaml)
  ↓
  WRITE answers file (YAML, "# trollbridge-init-answers v1" header)
  ↓
  RUN  trollbridge init --answers <file>
  ↓
  RUN  trollbridge ca init                       (if interception=true)
  ↓
  TELL user to run `sudo ... ca install`         (if interception=true)
  ↓
  TELL user to write LLM key file as trollbridge (if advisor=true AND daemon-mode)
  ↓
  RUN  trollbridge validate -c ./trollbridge.yaml
  ↓
  RUN  trollbridge doctor   -c ./trollbridge.yaml
  ↓
  RUN  trollbridge run      -c ./trollbridge.yaml     (or `systemctl start`)
  ↓
  RUN  trollbridge verify --json -c ./trollbridge.yaml
  ↓
  IF ok:  REPORT completion summary to user
  ELSE:   READ gaps[], SURFACE next_action[] for each blocking gap
```

## Cross-platform matrix

| Concern | Linux | macOS | Windows |
|---|---|---|---|
| Install binary | `curl ... install.sh` | `curl ... install.sh` | direct `.exe` download |
| user-mode | supported | supported | **only mode supported** |
| daemon-mode | supported (systemd unit ships) | unofficial (no launchd unit) | **NOT supported** |
| CA install automated | `--apply` | `--apply` (sudo) | manual `certutil` (Administrator) |
| Default config dir | cwd / `/etc/trollbridge/` | cwd / `/etc/trollbridge/` | cwd / `%ProgramData%\trollbridge\` |
| Firewall snippets ship | iptables / nftables | — | — |

On **Windows**, the agent MUST choose `install_mode: user`. The
plan refuses `daemon` on Windows; the existing `init` command
already prints a clear "not yet supported" message in that case.

## Avoiding unnecessary questions — heuristics

- **Don't ask** about audit log path unless the user mentioned
  log retention or a dedicated volume.
- **Don't ask** about `controller:` auth — mTLS is the only mode.
- **Don't ask** about redaction defaults; the static defaults are
  conservative.
- **Don't ask** about advisor `on_unavailable` / `confidence_floor`
  — accept defaults unless the user asks for fail-open behavior.
- **Don't ask** about `passthrough_hosts` until the user reports
  a service that pins certificates.
- **Don't ask** about structured rules / identities until the
  base setup is verified.

When in doubt, accept the default and move on. The user can
always edit `trollbridge.yaml` after the fact; the console REPL
edits `lists.allow` / `lists.deny` in place.

## Backward compatibility

Existing users keep their flows. Nothing in this onboarding path
breaks:

- `curl -fsSL https://trollbridge.dev/install.sh | sh` — works as before.
- `trollbridge init` (on a TTY) — interactive flow unchanged.
- `trollbridge quickstart` — 30-second start unchanged.
- Existing `trollbridge.yaml` files — load unchanged; no schema
  migration.

## Where this content lives (one source, many views)

| Artifact | Role |
|---|---|
| [`SETUP-AGENT.md`](SETUP-AGENT.md) | This file — the prose entry point. |
| [`config.agentic.yaml`](config.agentic.yaml) | The YAML template with the same decision tree as inline comments. |
| `internal/setupplan/plan.go` | The Go source of truth that `setup-plan --json/--yaml/--doc` renders. |
| `trollbridge setup-plan --json` | JSON view, for programmatic agents. |
| `trollbridge setup-plan --doc` | Markdown view (regenerable). |
| `trollbridge init --answers <file>` | Apply collected answers without a TTY. |
| `trollbridge verify --json` | Done-check after starting the proxy. |

If any of the four views disagree, the Go source wins; the test
suite asserts the views stay aligned.

## When something blocks

- **Build / install fails on a platform** — report the platform
  and the exact error to the user; reference the relevant note in
  the platform-notes section above.
- **Strict YAML decoder rejects an answer key** — the error names
  the field; fix the answers file and re-run.
- **`verify` says `proxy_unreachable`** — start the proxy first
  (`trollbridge run -c <path>`).
- **`verify` says `interception_ca_missing`** — interception is
  on but `trollbridge ca init` was not run, or was run on a
  different host. Surface `trollbridge ca init` to the user.
- **The advisor wire fails** — `trollbridge doctor -c <path>
  --check-llm` is the deeper test. Read the FAIL line; the
  error names the offending field (key, endpoint, or model).
