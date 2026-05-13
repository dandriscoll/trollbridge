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

### Forensics

- Held requests resolved after `signal_after_seconds` fires now write
  a follow-up audit entry sharing the original `request_id` (#97).
  The entry carries `post_signal_resolution: true` and
  `signal_after_seconds: <N>` (new omitempty fields on
  `audit.Entry`; `audit_schema_version` stays at 1).

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
