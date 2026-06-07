# Changelog

Notable behavior and contract changes between releases. Operator-facing
information first; implementation-only changes are not necessarily
listed here.

The full set of commits between any two tags is on GitHub at
`https://github.com/dandriscoll/trollbridge/compare/<from>...<to>`.

## Unreleased

## v0.9.1 — 2026-06-07

### Operator

- **`llm.endpoint` is validated at startup.** A public host must use
  `https` (a cleartext `http` endpoint to a non-private host is now
  rejected with a clear config error). An `http`/`https` endpoint that
  points at a loopback or RFC-1918 address still loads — for a local LLM
  advisor — but logs a startup warning. Unparseable or non-http(s)
  endpoints are rejected.
- **`trollbridge update` now verifies install.sh before running it.**
  The installer script is downloaded and checked against a SHA-256
  pinned in the binary; on mismatch nothing is executed and the error
  names the recovery step (reinstall manually, which self-verifies the
  binary). The pin is kept current by `scripts/release.sh`.

## v0.9.0 — 2026-05-31

### URL pattern model — Azure ARM and Azure Key Vault

Closes #203. Trollbridge now recognizes structured URL families before
rule evaluation and exposes the recognition in rules and the audit log.
Two built-in patterns ship:

- **`azure_arm`** — matches `management.azure.com` URLs and extracts
  `subscription`, `resource_group`, `provider`, `resource_type`, and
  `resource_name` from the canonical ARM path
  (`/subscriptions/.../resourceGroups/.../providers/...`).
- **`azure_keyvault`** — matches `*.vault.azure.net` and extracts the
  `vault` name.

Rules may reference a recognized pattern via two new Match clauses:

```yaml
- id: allow-arm-vm-reads-prod
  description: GET on virtual machines in the prod subscription
  match:
    pattern: azure_arm
    components:
      subscription: "12345678-1234-1234-1234-123456789abc"
      resource_type: virtualMachines
    method: GET
  effect: allow
```

`components` values are matched case-insensitively; `"*"` (or omitting
the key) matches any value. Unknown pattern names and component keys
are rejected at rule load with a clear error citing the rule ID.

The audit log records `pattern_name` and `pattern_components` on every
request that fits a known shape, regardless of which rule matched — so
an operator can grep all ARM traffic with `jq 'select(.pattern_name=="azure_arm")'`.

Operational log emits `event=pattern_match_eval` at INFO when a
pattern recognizes a request (per the ask-case telemetry completeness
rule). At startup, `event=patterns_registered` lists the registered
patterns.

**Forward-only schema:** rule files that use `match.pattern` /
`match.components` cannot be loaded by pre-v0.8.8 binaries (the strict
YAML decoder rejects unknown keys).

**Suggester also proposes pattern-shaped generalizations.** When the
allow or deny list accumulates ≥2 entries that fit a registered
pattern (azure_arm, azure_keyvault), the suggester groups them by
`(list, pattern, method)`, identifies the components that are
constant across the group, and offers a pattern-shaped suggestion
with the constants fixed and the varying components wildcarded.
Accepting writes a YAML rule to the first `policy.include` rule
file (with a deterministic `id: suggested-<pattern>-<short-hash>`)
and removes the source entries from the lists. Declining writes
the standard decline row so the same source set is not re-offered.

Pattern axes (`pattern:azure_arm`, `pattern:azure_keyvault`) rank
ahead of flat axes in the suggestion order, so the operator sees the
semantic suggestion first. The TUI suggestion card renders the
pattern name, fixed components, method, and source count.

If no rule file is configured under `policy.include`, accept returns
a clear error ("no rule file configured under policy.include"); the
flat-axis suggestion flow is unaffected.

New oplog event: `rule_added` (INFO) fires when a pattern accept
appends a rule, mirroring `allowlist_added`/`denylist_added` for
list mutations.

## v0.8.7 — 2026-05-30

### TUI no longer flickers on every refresh tick

- **The operator UI now uses line-level delta rendering.** Each tick
  emits only the lines that changed since the previous frame, not a
  full screen repaint. Steady-state ticks (no model change) emit zero
  bytes. The visible improvement is the elimination of the per-tick
  flicker reported in #202; long sessions are markedly easier on the
  eyes. A drift guard test asserts delta-render and full-render
  produce identical final screen state across structural model
  changes (closes #202).

### Quickstart now consolidates allow/deny on every operator action

- **`trollbridge quickstart`'s manual approve/deny flow now wraps
  list mutations in the same consolidate-then-add primitive that
  `trollbridge run` uses.** Pre-fix: approving a previously-denied
  host left the pattern on both lists; deny won on reload; the
  operator's approve silently no-op'd. Same #194 class as the run
  callback, missed by the original sweep because the
  multi-launcher audit (insight #28) was not yet wired. Surfaced
  by the new internal/lint structural test (closes #200's invariant
  2, in-job sibling fix).

### Cross-platform e2e matrix is now required on every PR

- **Windows and macOS e2e lanes are now required matrix lanes.**
  Previously the suite ran on Windows/macOS as a
  `continue-on-error` scratch lane; surfaced failures had to be
  read out of the logs manually. After Phase 2 fixes (`.exe`
  suffix on the test harness binary path; cross-OS portable
  audit-init test mechanism), both OSes pass the e2e suite
  consistently and now block PRs on any e2e regression
  (closes #163).

### Internal hardening (no operator-facing behavior change)

- **Alignment-principle enforcer tests + structural lint guards.**
  Each of the five principles in `docs/alignment-principles.md`
  now carries a code-citation line naming the enforcer test that
  fails on violation. New `internal/lint/` package adds AST-level
  build-time guards: `internal/advisor` cannot import
  `internal/configwrite` (§1) or `internal/hostlist` (§3); direct
  `configwrite.AddAllow` / `configwrite.AddDeny` calls outside
  the configwrite package fail the build; wire-bound prompt
  constants in `internal/advisor/prompts.go` and `translator.go`
  cannot contain "trollbridge"/"proxy"/"gateway"/"egress
  controller" (§4); `advisor.Classify` can only be invoked from
  `consultAdvisorForHold` in `internal/server/server.go` (§2)
  (closes #200, #201).

- **TUI LLM-panel scroll has subprocess pty coverage.** New
  `TROLLBRIDGE_TEST_INJECT_DIGESTS=N` env hook pre-fills the
  advisor digest ring with N synthetic entries; subprocess pty
  test exercises the LLM panel scroll dispatch + render math
  end-to-end against a 30-digest ring (closes #160).

## v0.8.6 — 2026-05-29

### Attach mode can now edit allow/deny lists

- **`trollbridge attach` no longer requires SSHing to the proxy host to
  approve, deny, or remove a URL.** New control-plane endpoints
  (`POST` / `DELETE` on `/v1/lists/{allow,deny}`) mutate the daemon's
  YAML via the same `OperatorApprove` / `OperatorDeny` primitive the
  in-process operator path uses, so the consolidate-then-add invariant
  from v0.8.5 also holds for attach mutations. The attach client's
  `allow` / `deny` console verbs now route through HTTP instead of
  printing "not available in attach mode" (closes #189).

### LLM auto-approval default raised to HIGH confidence

- **The LLM advisor now only auto-resolves a hold when the LLM reports
  HIGH confidence.** Prior default was MEDIUM. Operators wanting the
  prior behavior set `llm.confidence_floor: medium` in trollbridge.yaml.
  The advisor prompt also gained explicit guidance for what HIGH /
  MEDIUM / LOW mean — HIGH for semantically-close-to-approvals;
  MEDIUM for conceptually-related (other package-management registries,
  well-known services); LOW for standalone URLs (closes #195).

### LLM panel: sort toggle

- **Press `s` in the LLM panel to toggle the digest sort** between
  newest-first time (the default, current behavior) and URL-ascending.
  Selection survives the toggle (cursor anchored by request id,
  not index) (closes #198).

### Suggestion accept fires the standard list-mutation event

- **A suggestion-driven list mutation now also emits the
  `allowlist_added` / `denylist_added` oplog event** (with
  `source=suggestion`), alongside the existing `suggestion_accepted`
  event. Operators auditing list mutations can grep ONE event class
  for every list change, distinguishing origin via the `source` field
  (`tui` / `attach` / `suggestion`) (closes #172, #174).

### CI: Windows audit-file cleanup

- **Internal `server.Server.Close()` releases the audit-log file
  handle** so tests that construct a Server can defer cleanup. The
  prior Linux-only behavior allowed temp-dir deletion with the file
  still open; Windows refused, breaking the Windows CI lane (closes
  #199).

## v0.8.5 — 2026-05-29

### TUI columns no longer corrupt on ANSI-bearing cells

- **Status cells now render at their intended visible width.** The
  approvals pane's status column used to display fragments like `pendi…`
  with the timestamp displaced leftward when the colorized cell's ANSI
  bytes pushed the rune-counted truncation INTO the escape sequence. The
  cell is now sized by visible width directly via `padRightVisible`; the
  byte-buffer hack the bordered render path leaned on is gone (closes
  #197). The bug was pre-existing but amplified by the v0.8.4 reversal
  wrap and the #192-reopen blink rendering.

### LLM-checking now reads "thinking" with an immediate blink (re-closure of #192)

- **Waiting on the LLM is now immediately distinguishable from waiting
  on the operator.** The v0.8.4 spinner advanced one frame per ops tick
  (~1.5s) — too subtle, too slow. Replaced with the ANSI blink escape on
  a magenta `◌ thinking` cell; blink is terminal-managed and immediate.
  The wire-format `StatusChecking` value is unchanged — the term
  substitution is render-time only.
- **Reversal coloring now actually fires** when an operator-resolved
  decision contradicts a prior decision on the same host. Two bugs hid
  the v0.8.4 wrap from rendering: the TUI extracted the host WITH port
  (`example.com:443`) while the policy engine stores hosts without port;
  and operator-resolved decisions record with the verbose
  `ask_user_resolved_{allow,deny}` effect string while the TUI compared
  to the abbreviated `allow`/`deny`. Both now normalized.
- **`trollbridge quickstart` users get the reversal indicator too** —
  the previous wiring only landed in `trollbridge run`. Attach mode is
  still suppressed (needs an HTTP endpoint to expose history).

### Cursor sticks to pending across a burst-drain (re-closure of #191)

- **The cursor now snaps back to a newly-arriving pending row immediately**,
  even after a burst resolved every pending in the queue. The v0.8.4 fix
  correctly enforced the "stay on pending" rule within a single tick, but
  when a burst drained the entire pending list and a new pending arrived
  moments later, the cursor sat on resolved for ~6 seconds (until the
  existing idle-snap fired). A new sticky preference flag, latched while
  the cursor is on pending and cleared only by an explicit Up arrow,
  bridges that gap (closes #191 — re-closure after operator reopen).

### Suggester prefers a narrower allow when entries concentrate under one prefix

- **When 80% or more of a host's existing list entries cluster under a
  single 1-segment path prefix, the quiet-moment suggester now offers
  `host/<prefix>/*` instead of the broader `host/*`.** Previously the
  scorer always picked the broadest covering candidate, which
  overshoots when the operator has been approving (say) `api/*`
  exclusively and a single `webhook/*` outlier is the only thing
  pulling them apart. The threshold is tunable via
  `approvals.suggestion.path_concentration_threshold` (default 0.8);
  even-breadth lists continue to surface the broader allow (closes #190).

### Home and End jump the cursor to the first / last item

- **Home and End now navigate to the start and end of the focused
  list panel** — operations, urls, and llm. Previously the keys were
  recognized by the terminal but silently swallowed by the TUI's
  CSI parser. Recognized in every common terminal form
  (`ESC [ H` / `ESC [ F` and the VT-style `ESC [ {1,7} ~` /
  `ESC [ {4,8} ~`). The info pane is excluded — it shows per-op
  metadata, not a list (closes #196).

### List state now stays consolidated across every operator action

- **Approving a previously-denied URL now removes the deny entry**, and
  symmetrically denying a previously-approved URL removes the allow entry.
  Before this fix, the operator-approval persist callback wrote to one
  list without reconciling the other; the URL ended up on both lists and
  deny won on reload, silently negating the operator's action. The fix
  routes both the daemon's persist callback and the console's list-edit
  verbs through a single load-bearing primitive
  (`configwrite.OperatorApprove`/`OperatorDeny`), so a URL is never on
  both lists after any operator action (closes #194, recurrence-class
  closure for #179).
- **Sweep test added** to assert the consolidation invariant across every
  known operator-action persistence path. Adding a new persist path that
  bypasses the consolidation primitive will fail this test in CI before
  it can ship.

## v0.8.4 — 2026-05-29

### Security: the LLM advisor no longer mutates the allow/deny lists

- **Alignment principle §1 is now enforced in code.** The LLM advisor's
  allow/deny verdicts used to flow through `queue.ResolveByAdvisor` →
  the daemon's decision-persist callback → `lists.allow` / `lists.deny`
  YAML writes — an LLM that should only be deciding a single request
  was effectively granting itself persistent permissions. The advisor
  now resolves the hold without firing the persist callback, and a
  defense-in-depth guard in the callback layer rejects (and WARN-logs
  via the new `advisor_list_mutation_refused` event) any future regression
  that tries to re-wire that path (closes #193).

### Expanded TUI status colors

- **LLM-checking and human-waiting render differently now.** The approvals
  pane used to color both states the same yellow; the operator couldn't tell
  whether they were the blocker or the LLM was. `checking` rows now render
  in magenta with a small cycling Braille spinner, while `pending` stays
  static yellow (closes #192).
- **Decision reversals on a host are flagged in bright orange.** When a
  resolved row's effect contradicts a recent prior decision on the same
  host (you denied earlier, just approved, or vice versa), the row's status
  cell is wrapped in bright orange around the existing per-status color, so
  the inconsistency is visible at a glance. Render-time lookup against the
  daemon's existing in-memory decision history; per-host granularity for v1.

### TUI cursor now stays on the pending region across activity

- **The TUI cursor no longer drifts off the pending list when a
  background tick resolves the row the operator was on.** Approving a
  pending request used to land the cursor on the now-resolved row in
  the resolved section, forcing the operator to re-navigate to the
  next pending row before they could approve again. The cursor now
  rides any composition change — status flips, bursts of resolves,
  new pending arrivals — and only an explicit up-arrow keystroke
  moves it off the pending region (closes #191).

## v0.8.3 — 2026-05-25

### Declining a suggestion now sticks

- **Declining a quiet-moment generalization suggestion no longer
  re-offers the same candidate on the next detection cycle.** The
  decline wrote its suppression row to disk but the daemon kept scanning
  its pre-decline, in-memory list, so the suggestion reappeared
  immediately — the operator could never dismiss it. Decline now
  refreshes the daemon's config the same way Accept does (closes #188).
- **Fixed the decline status line reading "suggestion declineed".** It
  now reads "suggestion declined" (closes #187).

## v0.8.2 — 2026-05-25

### Generalize suggestions prefer host-wide coverage first

- **The quiet-moment generalizer now offers a host-wide `host/*`
  suggestion before any narrower per-path subset** when a host's
  entries span more than one path prefix. Previously the detector got
  stuck at the deepest common path prefix and could suggest a subset
  (`api.example.com/v1/users/*`) — or nothing at all when each deep
  prefix had a single entry — never the pattern covering every request
  to the host. Candidate groups are now ranked by how many existing
  list entries they subsume, so the broadest generalization is offered
  first; declining it walks to the narrower options (closes #186).

### TUI pending-list placement + resilient approve

- **Pending holds now float pinned to the bottom of the operations
  pane**, like the generalize/suggestion card, so they stay on screen
  no matter how many resolved operations scroll above them — no more
  scrolling a long history to reach the queue. The cursor enters the
  pending region by moving down past the last resolved row and leaves
  it by moving up off the top pending row (closes #185).
- **Approving a hold that was already resolved no longer errors with
  "hold not found".** A hold can be resolved out from under the
  operator (timeout, advisor, double-press) while its row still shows
  pending; the hold id is just a pointer. Pressing `a` / `d` on such a
  row now falls back to writing the request URL to the allow / deny
  list — the same write path as the retroactive add on a resolved row —
  so the action succeeds (closes #184).

## v0.8.1 — 2026-05-25

### Generalize re-offer + ip_block fixes

- **Accepting a generalize suggestion no longer re-offers the same
  suggestion.** The daemon's post-write reload refreshed the matcher
  but not the in-memory config the suggestion engine reads, so the next
  quiet-moment scan saw the pre-accept list and re-suggested the
  generalization it had just applied. Internal-write reloads now refresh
  both (closes #183).
- **Dropped the `ip_block` generalization axis** (#181). It emitted
  `/24` CIDR patterns that the host matcher could not match — an
  accepted block matched nothing and never pruned its member IPs.
  Generalization now offers hostname-below-TLD, URL-segment, and method
  only; IP literals are left as-is.

### Other

- **`trollbridge upgrade` is now a synonym for `trollbridge update`**
  (#182).

## v0.8.0 — 2026-05-24

### Suspend the TUI to the shell (closes #176)

- **Press `z` in the approvals pane to background trollbridge** via job
  control (SIGTSTP); `fg` resumes it and repaints. Bound to `z` rather
  than Ctrl-Z (which the URLs pane uses for undo) and only in the
  approvals pane, so a literal `z` typed into the console is never
  stolen. No-op on Windows, which has no job control.

### Advisor metrics (closes #137)

- **The LLM advisor now keeps process-lifetime counters** — consulted,
  classified (actionable allow/deny), fallback (consulted but landed on
  ask_user), and per-class errors (wire/schema/unknown) — plus a
  classify-latency histogram. Surfaced on the control plane at
  `GET /v1/advisor/metrics`.

### Other

- Daemon-suggested list mutations are now tagged `source=suggestion` on
  the accept oplog line too (not only on persist failure), so a
  suggested change can be told from a manual one (#172/#174).

## v0.7.21 — 2026-05-24

### Generalize + allow/deny workflow fixes

- **Generalize now prunes every redundant entry it covers, not just the
  selected ones (closes #177).** Accepting a generalization removes every
  existing allow/deny entry the new wildcard subsumes — across a widened
  method, dropped port, wildcarded path segment, or wildcarded hostname —
  so the list shrinks the way "generalize" implies. (IP `/24` blocks are a
  known gap — see #181.)
- **Approving a URL no longer leaves it stuck on the deny list (closes #179).**
  Adding a pattern to one list now removes it from the other, so an approved
  URL isn't silently overridden by a stale deny entry on the next reload.
- **`Enter` accepts and `Esc` cancels in the generalize card (closes #178).**
- **Transient status lines time out (closes #180).** The info line at the
  bottom of the operations pane (e.g. `generalized → allow …`) now clears
  after ~12s instead of lingering until the next action.

## v0.7.20 — 2026-05-20

### TUI: pending requests stay on screen in a busy ops pane (closes #175)

- **Fixed.** When the operations pane had more rows than fit, the
  pending (held) requests — sorted to the bottom of the list — were
  pushed off-screen with no way to scroll to them. The pane now
  bottom-anchors its scroll so the pending region is always visible at
  the bottom; navigating up with `j`/`k` follows the cursor into the
  resolved rows above.

## v0.7.19 — 2026-05-20

### Generalize accept now prunes the specifics it replaces (closes #173)

- **Changed.** Accepting a generalization (manual card or daemon
  suggestion) now removes the more-specific entries it replaces and
  adds the wildcard, in one atomic write — so the allow/deny list
  shrinks instead of growing. Previously the wildcard was added but the
  specifics were left behind. The confirmation names how many entries
  were pruned.

### TUI surfaces daemon generalization suggestions (#172)

- **Added.** The daemon's quiet-moment generalization suggestions now
  appear as a card in the operations pane. Accept with `shift+a` or
  decline with `shift+d`. The card is width-fit (no off-screen text) and
  is hidden whenever a request is pending approval, so it never competes
  with approve/deny. Works in both `trollbridge run` and `attach`.

### On-demand "suggest now" (#174)

- **Added.** Press `s` in the URL pane to ask the daemon to scan the
  allow/deny lists for a generalization immediately, rather than waiting
  for a quiet moment; the result appears in the suggestion card. An empty
  scan reports "no generalization opportunities found". Backed by a new
  `POST /v1/suggestion/scan` control endpoint.

## v0.7.18 — 2026-05-20

### TUI: modifier-arrow keys no longer hijack the panel (closes #171)

- **Fixed.** Pressing Shift-Up (or any modified arrow) in the URL pane
  no longer opens an inescapable info panel. The terminal sends
  Shift-Up as a modifier escape sequence (`ESC [ 1 ; 2 A`); the input
  parser used to leak its tail as the keystrokes `;`, `2`, `A`, and the
  stray `2` opened the info panel. The parser now consumes the whole
  sequence; unknown sequences are swallowed instead of leaking.
- **Fixed.** The info panel is no longer a dead end. Opening it from the
  URL or LLM pane left keyboard focus on the bottom pane, where the
  number keys did nothing and only Esc closed the panel. The info panel
  now behaves like every other panel — `0`-`4` switch panels and Esc
  closes, from any entry point.

### TUI: usable generalize workflow in the operations pane (#170)

- **Added.** Pressing `g` in the URL pane opens a generalization card in
  the operations pane (no more options pushed off-screen). On a single
  selected URL it proposes generalizations across axes — path segment,
  hostname-below-TLD, IP /24, and method — and `tab` rotates between
  them. Shift-Up / Shift-Down select a contiguous range of URLs, and
  `g` then runs the deterministic detector over just that selection.
- **Card keys.** `a` accepts (adds the pattern to the allow/deny list),
  `d` or Esc dismisses, `tab` rotates the axis. The selected range is
  dimmed in the URL list.
- The LLM-backed "suggest generalizations" entry point is tracked
  separately in #172.

## v0.7.17 — 2026-05-19

### Pair-with-a-sandbox documentation (closes #169)

- **README.** New "Pair with a sandbox" section between "What it
  does" and "Get started." Names the trollbridge × agent-isolation
  pairing explicitly, lists Incus / Podman / Lima / OrbStack / Tart
  / Multipass / WSL2 / Hyper-V as starting options, and respects
  the operator who has already chosen not to sandbox by naming the
  hold-and-approve + audit log as the safety net.
- **`docs/deploy.md`.** Topology-choice table now leads with the
  isolation framing and gains an explicit "local-isolation profile"
  column distinct from network-isolation strength. The Incus VM
  topology stays the recommended happy path.
- **`/src/dan/TROLLBRIDGE_DESIGN.md`** (private design doc) gains
  `S8` (deploy-side directive for trollbridge.dev) and `R6`
  (records the README + deploy.md changes). The deploy-side
  trollbridge.dev "Pair with a sandbox" section is filed for the
  deploy-repo author to land.

### Generalization → quiet-moment suggestion mode (closes #168)

- **Removed.** The post-approve `[1]all methods [2]all URLs on host
  [3]both` keystroke prompt that fired immediately after pressing
  `a` to approve a hold. The interruption competed with the
  operator's primary task; the URL pane's explicit `g` "generalize
  this entry" command was also retired.
- **Added.** A daemon-owned quiet-moment suggestion lifecycle.
  When the proxy has been idle (queue empty AND no inbound request)
  for `approvals.suggestion.quiet_idle_seconds` (default 30), a
  deterministic detector scans the allow and deny lists
  independently for any of four closed-set axes — hostname below
  the TLD, IP block (/24), URL segments, or HTTP methods — and
  offers one suggestion per quiet moment. Accept persists the
  pattern via the existing `configwrite` path; decline either
  rotates to the next applicable axis for the same source set OR
  writes a row to the new auto-managed `lists.declined_suggestions`
  section so the same set is never re-offered.
- **YAML schema.** New `lists.declined_suggestions` section with a
  header comment marking it auto-managed. Each row records the
  sorted `source_entries` set, the `axes_declined` during the
  cycle, and a `declined_at` RFC3339 timestamp.
- **Telemetry.** Nine new event constants in `internal/oplog/events.go`
  cover every phase at INFO (DEBUG when the quiet predicate doesn't
  fire). Mirror of the ask-case completeness rule from #25/#33/#34/#35.
- **Control plane.** New endpoints `GET /v1/suggestion`,
  `POST /v1/suggestion/accept`, `POST /v1/suggestion/decline`.
- **Alignment principle preserved.** The LLM advisor (when wired)
  only ranks and narrates among candidates the deterministic
  detector has already produced; the advisor cannot invent a pattern
  not in the input. `docs/alignment-principles.md` §1 (allow/deny
  lists are human-only) remains intact because the mutation gate is
  the operator's explicit Accept. v1 ships the deterministic
  ranking path; LLM-translator integration is a follow-up.

## v0.7.16 — 2026-05-18

### Policy

- `prior_decision` rule clause now matches only human + static-policy
  prior decisions; LLM-advisor verdicts are filtered out at the
  recording boundary (#141 — see v0.7.15 entry for the original
  closure; this release adds the audit-side complement).

### Audit / observability

- `audit.Logger.Close` emits an INFO `audit_logger_close_summary`
  line at shutdown when the OverflowDrop or level-filter counters
  are non-zero (#143 part d / #167). Quiet on clean shutdown.
- `trollbridge decisions` CLI now applies the live `audit_level`
  filter when reading the audit log (#143 part c / #167). Pre-
  existing static-policy entries from a prior run with
  `audit_level=all` are no longer shown when the current setting
  is `decisions`.

### Telemetry

- `advisor_classified` INFO log line carries `latency_ms` — the
  provider-side classify-call duration (#137 side item).
- Digest-ring entries carry `llm_input_hash` so the audit log and
  digest ring share a single correlation key (#137 side item).

### Reload status

- `reloadstatus.Tracker` keeps per-source state; `Status` gains a
  `failing_sources` slice (json, omitempty); the TUI badge stacks
  one entry per failing source when multiple sources are
  simultaneously failing (#165). `/v1/rules` JSON gains
  `failing_sources` under the same omitempty rule.

### Test coverage

- E2E tests for the remaining startup_failure branches (audit_level
  / server / lists) via the `TROLLBRIDGE_TEST_FAIL_STAGE=<stage>`
  env hook (#146 / #166).
- Subprocess e2e: `trollbridge logs review` filters static-policy
  entries (#162).
- E2E: `audit_level: decisions` filters static-policy entries on
  disk (#161).

### CI

- New scheduled workflow `install-smoke.yml` walks the README's
  `curl | sh` install path on Linux + macOS weekly (#152).
- Cross-platform e2e scratch lane on Windows / macOS via
  `continue-on-error: true` to surface what fixing the suite there
  would require (#163 Phase 1).

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
