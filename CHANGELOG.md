# Changelog

Notable behavior and contract changes between releases. Operator-facing
information first; implementation-only changes are not necessarily
listed here.

The full set of commits between any two tags is on GitHub at
`https://github.com/dandriscoll/trollbridge/compare/<from>...<to>`.

## Unreleased

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

- `CLIENT-SETUP-AGENT.md` Step 1 now documents two scopes for the
  proxy env vars (#116). Shell-wide (existing `export …` pattern)
  for the convenient case; per-process / agent-scoped (the
  `VAR=val … <command>` shell prefix and a PowerShell equivalent)
  for agents that should not pollute the operator's interactive
  shell. The trade-off is named in one line so the reader can pick
  the right scope.

### TUI

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
