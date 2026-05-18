# Changelog

Notable behavior and contract changes between releases. Operator-facing
information first; implementation-only changes are not necessarily
listed here.

The full set of commits between any two tags is on GitHub at
`https://github.com/dandriscoll/trollbridge/compare/<from>...<to>`.

## Unreleased

## v0.7.15 — 2026-05-18

### Audit shape

- `decision_source` no longer reads `"default"` on TLS handshake
  failure, malformed-tunnel HTTP, or body-read-failure paths (#139).
  Those three paths now carry distinct values: `tls_handshake_fail`,
  `malformed_tunnel`, and `body_read_fail`. `default` retains its
  narrow meaning of "no rule matched, default mode applied."
  Operator dashboards filtering for failure paths by
  `decision_source=default` must update to the new values.
- Audit entries from the proxy→origin TLS path now carry
  `tls_error_category` (#138) — previously only client→proxy TLS
  failures populated this field. The category distinguishes
  `upstream_cert_invalid` / `upstream_connect` / `unknown` for
  operators triaging origin handshake failures.

### Policy

- `prior_decision` rule clause no longer matches prior LLM advisor
  verdicts (#141). The match surface is scoped to human +
  static-policy decisions; an LLM verdict that resolved a previous
  request cannot be silently re-applied by a deterministic rule
  without re-consulting the advisor.

### Observability

- `audit.Logger.LevelFiltered()` returns a per-process counter of
  entries the audit-level filter dropped (#143 part a). Distinct from
  `Dropped()` (OverflowDrop budget-exceeded drops). Lets an operator
  confirm filtering is engaged vs. silently losing entries.
- On startup, when `audit_level != all`, the operational log emits
  `event=audit_level_filter_active` once (#143 part b) so an operator
  seeing fewer audit entries than expected reads the cause inline.

### CI / tooling

- New CI lanes (Linux): `scripts/check-model-strings.sh` catches
  hardcoded model identifiers outside the wizard / translator
  allowlist (#155); `scripts/check-doc-links.sh` validates every
  relative markdown link across the repo's `*.md` files (#151).
  Both are exposed as `make` targets.
- Optional pre-commit hook (#154): `scripts/precommit-check.sh`
  refuses to add staged files over 5 MiB. Override per-commit with
  `TROLLBRIDGE_LARGE_FILE_OK=1`. Install via
  `ln -s ../../scripts/precommit-check.sh .git/hooks/pre-commit`.
- New gated test lane: `go test -tags=live_az ./cmd/trollbridge/`
  exercises the real `az` CLI's JSON shape so the wizard's
  Cognitive-Services parsers stay locked to Azure's actual
  responses (#148).

### Telemetry

- `advisor_consulted` and `advisor_classified` log lines carry a
  new `model` attribute (#157) — the AOAI deployment name (parsed
  from the endpoint URL) or the configured `llm.Model` for other
  providers. Multi-deployment AOAI operators can now attribute
  log entries by deployment. Attribute is omitted when the
  advisor service has no configured ModelIdentifier (back-compat).

### TUI

- The approvals-pane reload-failed badge now names the failing
  source (#145): `␇ config reload failed` / `␇ rules reload failed`
  / `␇ lists reload failed` instead of the bare `␇ reload failed`.
  Unknown / legacy-empty source falls back to the bare badge.
- Internal refactor: shared `formatOpRow` helper consolidates the
  approvals-pane row formatting that bordered and no-border
  renderers previously duplicated (#142). No visual change.

### Test coverage

- `internal/control/control_test.go` gains HTTP integration tests
  for `/v1/rules` across the three reload-status states (#144).
- Subprocess pty test for Ctrl-L hard-clear sequence (#159).
- E2E test exercising `trollbridge verify --json` against a running
  daemon (#149).
- E2E test exercising the audit-init startup_failure branch (#146
  partial). Remaining branches tracked in #166.

### Init

- `init` AOAI provider flow now surfaces a one-line note before
  the model prompt (#158): the deployment name in the endpoint URL
  drives routing; the `model:` field is informational for AOAI.

### Release tooling

- `scripts/release.sh --build-only` (#153). Skips clean-tree
  preflight and the bump/tag/push/publish flow; runs `build_matrix`
  against the current version so implementers can verify
  matrix-output without dirtying release semantics. Mutually
  exclusive with the other release-flow flags.

### Docs

- README opening rewritten to unify voice with trollbridge.dev: the
  tagline ("Let your agents run amok — but only where you say") and
  the three pillars (read/write/run · outbound only where you say ·
  hold the rest for one keystroke) now mirror the site's three
  feature panels. The technical "policy-governed conditions"
  framing moves into the body. README also gains a badges row
  (release / ci / license / go version) and a one-line summary
  over the audience-routing block. No CLI behavior changed.

### Release process

- GitHub release bodies are now sourced from CHANGELOG.md `## Unreleased`
  via `gh release create --notes-file` rather than the prior
  `--generate-notes` which had degraded to bodies reading only
  `**Full Changelog**: <compare-link>` for v0.7.10..v0.7.14.
  `scripts/release.sh` now preflights that `## Unreleased` is non-empty
  and fails closed otherwise, promotes the section to a versioned
  heading (`## vX.Y.Z — YYYY-MM-DD`), and includes CHANGELOG.md in the
  release bump commit. Producer-side contract documented in
  `AGENTS.md`: operator-visible changes add their CHANGELOG entry in
  the same commit, not deferred to release time.

### Wire / TUI

- `/v1/lists` and `/v1/llm-digests` control-plane endpoints (#99). The
  attach-mode TUI's URLs and LLM panels now render against a remote
  daemon. Existing consumers that did not exercise either endpoint
  are unaffected.
- `Trollbridge-Discovery` header on every 470 / 471 response (#95).
  Points at `http://config.trollbridge.dev/discovery`, a new JSON
  document describing the wire protocol (status codes, headers,
  body shapes, audit-log correlation). Existing agents that ignore
  unknown headers continue to work unchanged.

### Operator

- `trollbridge update --prefix <dir>` (#108 part 1). Forwards the
  given directory as `TROLLBRIDGE_INSTALL_DIR` to install.sh so the
  binary lands where the operator chooses rather than install.sh's
  default. The cross-repo install.sh PATH detection is tracked
  separately.
- `trollbridge update --check` (#102 part 2). Prints the latest
  released version without invoking the installer.
- `trollbridge update` now classifies failures and prints a one-line
  hint above the wrapped error (#102 part 1): network /
  bash_missing / permission_denied / signature_mismatch / unknown.
- `init` daemon-mode on Windows now emits a clear refusal instead of
  POSIX commands the operator cannot execute (#101 part 2). Pick
  user-mode at the install-mode prompt; daemon-mode-Windows is
  tracked separately.
- Hot-reload now covers `mode` and the `approvals` knobs
  (`timeout_seconds`, `signal_after_seconds`, `on_timeout`,
  `max_pending`) in addition to lists + rules (#111). Restart-only
  sections are documented in `internal/server/server.go`
  `HotReloadableSections`.
- External-edit detection migrated from mtime polling to fsnotify
  (#110). Detection latency drops from the previous 2s floor to
  ~50ms (the debounce window).
- Config and rule files are now decoded strictly (#123). A YAML key
  with no matching field — a typo (`mod:` for `mode:`), or an
  unsupported block — fails the load loudly instead of being silently
  discarded; `trollbridge validate` now reports the offending key and
  line instead of `OK`. **Operator-visible breaking change:** a config
  or included rule file carrying an unknown or forward-compat key that
  previously loaded will now error on `run`, `validate`, and
  hot-reload — run `trollbridge validate` to find the offending key,
  then remove or correct it. On the hot-reload path the reload fails
  and the prior config/rule set is kept (the daemon does not crash).
- Config and rule files with more than one YAML document now fail the
  load (#126). `---`-separated documents after the first were silently
  ignored — the same silent-drop class as #123 at document
  granularity. A bare trailing `---` separator with no content is
  still accepted. **Operator-visible breaking change** for anyone who
  split a config or rule file into multiple documents: keep one
  document per file.
- `trollbridge run` now emits a structured `config_load_failure`
  operational-log event when it cannot load its config or open its
  operational log at startup (#128). Previously these pre-startup
  failures reached stderr only, with no structured event — a daemon
  that failed to start left no operational-log record of why.
- Rule files containing `match.tool` now fail to load (#125). The
  field was parsed but never evaluated — a `tool:` clause was a
  silent no-op. With strict YAML decoding (#123) the same clause now
  surfaces as a parse error naming `tool`, so the operator can edit
  the line out instead of believing a non-functional rule was active.
- `trollbridge init` interactive wizard now defaults the `model:`
  prompt by provider (#131). Azure OpenAI does not serve Claude
  models, but the wizard had been suggesting `claude-opus-4-7` after
  the operator picked `aoai`. New defaults: `claude-opus-4-7` for
  anthropic (unchanged), `gpt-4o-mini` for aoai, empty for `other`.
  Operators who type the model name they actually want are
  unaffected.
- Windows release artifacts now ship as a bare `.exe` instead of a
  `.tar.gz` containing `trollbridge.exe` (#130). The Linux/macOS
  release shape is unchanged — those still get
  `trollbridge_v<X.Y.Z>_<os>_<arch>.tar.gz`. Windows operators with
  bookmarked tarball URLs from prior releases will need to point at
  the new `trollbridge_v<X.Y.Z>_windows_<arch>.exe` asset.
- `trollbridge validate --json` emits a single JSON object on stdout
  with the same shape as the existing human summary (#127). The
  exit-code contract is now documented in the command help and in
  the README: `0` = valid, `1` = invalid (any reason). Operators
  binding config-lint from their own CI now have a stable surface.
- `trollbridge run` now emits a structured `startup_failure`
  operational-log event when it fails to construct after the
  operational log is open (#134). Sibling to #128, which covers the
  *pre*-opLog slice (`config_load_failure`). The new event covers
  `policy.NewEngine`, `audit.New`, `audit.ParseLevel`,
  `server.NewWithLoggers`, and inline-list parse failures; each
  carries a `stage` attribute (`policy` / `audit` / `audit_level` /
  `server` / `lists`). Operators alerting on "daemon failed to
  start" should extend their `config_load_failure` query to
  include `startup_failure`.
- `trollbridge init` interactive wizard now hints when `az` is
  installed but the operator is not authenticated (#136). On the
  `aoai` provider branch, the wizard distinguishes "no `az` in
  PATH" (still a silent skip, unchanged) from "`az` present but
  `az account show` fails" — the latter now prints a one-line
  transcript hint suggesting `az login` and a re-run, then falls
  through to the existing manual prompts. Operators who would
  have benefited from the find/create shortcut now know it is
  one `az login` away.
- `trollbridge init` interactive wizard now offers to find or
  create an Azure OpenAI deployment via the `az` CLI when the
  operator picks `aoai` as the provider (#132). Detection: `az`
  in PATH AND `az account show` succeeds; otherwise the wizard
  silently falls back to the manual endpoint / key prompts. The
  `find` branch lists the operator's existing OpenAI accounts and
  deployments and pre-fills endpoint / model / (user-mode) API
  key from the selection. The `create` branch walks them through
  resource-group + account-name + region (default `eastus`) +
  deployment-name and provisions via `az cognitiveservices`
  commands. Operators who want the manual flow pick `skip`. Az
  must be logged in to the desired subscription before init
  starts (`az account set --subscription <id>` if multiple).
- `make llm-test` (new) runs the LLM-advisor regression suite
  against the live LLM configured by your `trollbridge.yaml`
  (closes #133). Point `TROLLBRIDGE_LLM_TEST_CONFIG` at the
  config, then `make llm-test`. Bundles under
  `llmtest/bundles/*.yaml` declare directives + allow/deny
  context + cases with expected verdict (`allow`/`deny`/
  `ask_user`) and confidence band (`low`/`medium`/`high`). The
  framework dispatches one live LLM call per case and reports
  per-case pass/fail — catches prompt drift, model-version
  drift, and subtle policy gaps. Three starter bundles
  (baseline / security / grey-area) ship by default; add your
  own under `llmtest/bundles/`. See `llmtest/README.md`.

### Forensics

- Held requests resolved after `signal_after_seconds` fires now write
  a follow-up audit entry sharing the original `request_id` (#97).
  The entry carries `post_signal_resolution: true` and
  `signal_after_seconds: <N>` (new omitempty fields on
  `audit.Entry`; `audit_schema_version` stays at 1).
- `logging.audit_level` knob (#113). Three levels: `all` (default;
  current behavior), `decisions` (only entries from a human or the
  LLM advisor — static-policy auto-decisions dropped at enqueue),
  `none` (drop every entry). Omitting the key preserves the
  pre-#113 behavior; existing deployments are unaffected on
  upgrade. Invalid values fail config validation at startup.
- `trollbridge logs review` subcommand (#114). Lists audit entries
  from human or LLM decisions in chronological order, with
  reasoning and (for LLM entries) model / confidence / input-hash
  trace. Static-policy auto-decisions filtered out. Shares the
  `(DecisionSource).IsHumanOrLLM()` categorization with the new
  `audit_level: decisions` filter (#113). `--since <duration>`
  applies a cutoff; `--config -c` overrides the default config
  path.

### Docs

- README rewritten as a first-time-reader front door (#135). The
  page is now ~130 lines (was ~390), organized as: what trollbridge
  is, an audience map ("agent is installing for me" /
  "installing on my own machine" / "deploying to a host"),
  install / run / verify, and a compact "Where to go next" doc map.
  Operator-deep content moved to two new docs:
  [`docs/operator-ui.md`](docs/operator-ui.md) (TUI keymap, daemon
  mode, attach, console REPL, CI validation via
  `trollbridge validate`) and
  [`docs/self-describing.md`](docs/self-describing.md)
  (`config.trollbridge.dev/*` bootstrap endpoints). Hosts /
  CA / mTLS / TLS-interception specifics link to the existing
  [`PROXY-SETUP-AGENT.md`](PROXY-SETUP-AGENT.md). No CLI behavior
  changed; the agentic-setup URL and curl-pipe installer
  command are preserved verbatim.
- `CLIENT-SETUP-AGENT.md` Step 3 no longer claims the README has
  per-runtime trust-bundle snippets (Python `certifi`, Node
  `NODE_EXTRA_CA_CERTS`, Java `cacerts`) — it never did. The
  reference now points at `DESIGN.md` §7.5, which does carry the
  list. Embedded copy in `internal/selfdescribe/` updated in
  lock-step so the drift test stays green.
- `CLIENT-SETUP-AGENT.md` Step 1 now documents two scopes for the
  proxy env vars (#116). Shell-wide (existing `export …` pattern)
  for the convenient case; per-process / agent-scoped (the
  `VAR=val … <command>` shell prefix and a PowerShell equivalent)
  for agents that should not pollute the operator's interactive
  shell. The trade-off is named in one line so the reader can pick
  the right scope.

### TUI

- Approvals-pane header gains a `␇ reload failed` badge when the
  daemon's last hot-reload attempt errored (#129). Same red-bold
  style as the existing pending-count indicator (#72) so the badge
  is visible from across the room. Operators editing the config to
  tighten policy now have a visual cue when their edit did not take
  — the silent-divergence exposure the issue named (since strict
  decoding, #123, made reload failures more likely on operator
  typos) is now operator-observable, not log-only. Badge clears on
  the next successful reload; no dismiss key by design. The
  server's `/v1/rules` response carries `last_reload_error`,
  `last_reload_at`, `last_reload_source` (omitempty) — backwards-
  compatible with existing consumers.
- LLM panel now scrolls correctly when the selection moves below
  the visible newest-first window (#117). The selection
  (DigestSelected) was always moving on Up/Down/j/k — the
  renderer just iterated strictly from the newest digest and
  stopped at the body row budget, so past that point the operator
  saw no change. Anchor-at-bottom scroll keeps the selected
  digest visible; the modal-mode render (Enter-expanded, detail
  doesn't fit inline) was already correct and is unaffected.

## v0.7.1 — wire-format changes operator scripts may notice

The following changes shipped in v0.7.1 and may affect operator
scripts. They are documented here so a quick `git log` / changelog
read catches them.

- **`/v1/ops` decision strings changed.** Numeric strings `"470"` and
  `"471"` were replaced with categorical `"denied"` and `"signaled"`.
  Operator scripts that grep the `/v1/ops` JSON for the digits will
  miss these entries; update to grep the categorical tokens.
- **LLM tool name renamed.** The LLM advisor's tool name changed
  from `trollbridge_decision` to `classify_request`. Operators with
  per-tool restrictions configured at their LLM provider need a
  one-line config update to the new name.
- **Pattern syntax accepts method prefixes.** Pattern files written
  with the TUI may now contain method prefixes (e.g.,
  `GET https://api.example.com/v1/*`). Older binaries cannot parse
  the new form; roll all consumers to this version or later before
  relying on the TUI's post-approve generalization to write method-
  prefixed patterns.
