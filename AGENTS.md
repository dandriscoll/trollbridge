# AGENTS.md

Instructions for an LLM-driven coding agent working **on the
trollbridge codebase** — building, testing, refactoring, fixing
bugs.

If you are a different kind of agent, you want a different file:

- An agent **setting up the trollbridge proxy** (running `init`,
  configuring policy, generating the CA): see
  [`PROXY-SETUP-AGENT.md`](PROXY-SETUP-AGENT.md).
- An agent **pointing its own egress at a running trollbridge** (env
  vars, CA install, verification): see
  [`CLIENT-SETUP-AGENT.md`](CLIENT-SETUP-AGENT.md). Once the proxy
  is running, the same content is fetchable from
  `http://config.trollbridge.dev/setup/instructions.md` *through*
  the proxy.
- An agent whose own HTTP/HTTPS egress **goes through trollbridge**
  (the LLM runtime calling out to the network): see
  [`PROXIED-AGENT.md`](PROXIED-AGENT.md). Also fetchable from
  `http://config.trollbridge.dev/setup/proxied-agent.md`.

The rest of this file is for producers — coding agents working on
trollbridge.

## What trollbridge is

A single static Go binary that runs an HTTP/HTTPS forward proxy
gating an agent's network egress against a deterministic policy,
with an optional LLM advisor classifying ambiguous requests. The
authoritative spec is [`DESIGN.md`](DESIGN.md).

## Repo layout

```
cmd/trollbridge/        # Cobra CLI commands (run, init, ca, test, …)
internal/server/        # proxy core: dispatcher, intercept, refusal
internal/advisor/       # LLM advisor: translators (anthropic, aoai), HTTPClassifier
internal/policy/        # rule engine, history, time windows
internal/config/        # YAML schema (v3) + loader + Bind parser
internal/console/       # operator command backend (allow/deny/list/test/doctor); driven by tui's console pane
internal/control/       # mTLS control plane (approve/deny/sessions/attach)
internal/controlclient/ # client side of the control plane
internal/ca/            # CA generation, leaf signing, fingerprinting
internal/hostlist/      # allow/deny pattern matcher
internal/audit/         # JSON-lines audit log writer
internal/oplog/         # structured operational logger (slog)
internal/redact/        # body / query redaction
internal/identity/      # identity resolver (mTLS / bearer / source IP)
internal/sessions/      # per-client session tracker
internal/types/         # shared types (Effect, Decision, RequestEvent)
internal/tui/           # unified two-pane operator UI (approvals + console); raw alt-screen, hand-rolled ANSI
internal/configwrite/   # in-place YAML edits that preserve comments outside the touched subtree (console-pane writes)
internal/envprint/      # render shell exports for HTTP(S)_PROXY
packaging/              # systemd unit, Dockerfile, Incus cloud-init, firewall
scripts/release.sh      # end-to-end release flow (bump → tag → build → publish)
docs/deploy.md          # deployment recipes (user-mode dev, Incus, sidecar, systemd)
```

## Build & test

```sh
make build                                    # static binary at bin/trollbridge
go test ./...                                 # default lane: ~12s, server suite dominates
go test -tags=e2e ./cmd/trollbridge/...       # full CLI E2E: compiles binary, spawns it,
                                              #   sends real proxied requests, checks audit log
go test -tags=twinslive ./internal/advisor/   # wire-layer against anthropic.twins.la / aoai.twins.la
                                              #   needs ANTHROPIC_TWIN_API_KEY (and AOAI_TWIN_*)
go test -tags=live_az ./cmd/trollbridge/      # live `az` CLI shape pin (#148)
                                              #   needs az on PATH + `az login`
make vet
make tidy
make check-model-strings                      # lint hardcoded model strings (#155)
make check-doc-links                          # validate relative *.md links (#151)
```

The binary embeds its version via ldflags (`-X
github.com/dandriscoll/trollbridge/internal/server.Version=…`).
`make build` derives the version from `git describe`; release
builds use the script.

### Pre-commit hook (optional)

`scripts/precommit-check.sh` refuses to add any staged file larger
than 5 MiB without an explicit override (#154). Install it as a git
hook:

```sh
ln -s ../../scripts/precommit-check.sh .git/hooks/pre-commit
```

When a legitimate large addition is needed (tagged binary artifact,
vendored test fixture), override per-commit:

```sh
TROLLBRIDGE_LARGE_FILE_OK=1 git commit ...
```

Set `TROLLBRIDGE_LARGE_FILE_LIMIT=<bytes>` to change the default.

## Wire contract — do not change without intent

The proxy emits two non-standard HTTP status codes that consuming
agents are documented to recognize:

- **470** — declined (deny effect or its variants).
- **471** — pending approval (ask_user / ask_llm effects).

Both are unassigned in IANA's HTTP Status Code registry. The
trollbridge JSON refusal body is `{effect, request_id}` only; the
`Trollbridge-Reason` header is the categorical effect token only
(`declined` or `pending`). The reason text and rule id live in the
audit log, not on the wire.

Changing these codes or the body shape is a wire-contract bump and
should be a major version. The constants live in
`internal/server/refusal.go` (`StatusTrollbridgeDeclined`,
`StatusTrollbridgePending`).

## Conventions

- **Go 1.26+**, single module, no internal vendoring.
- **Errors are sentinel-typed** for exit-code routing:
  `configErr` → exit 1, `runtimeErr` → exit 2, `holdNotFoundErr`
  → exit 3. See `cmd/trollbridge/root.go`. New error paths should
  pick one of these and wrap.
- **No comments unless the WHY is non-obvious.** A hidden
  constraint, a workaround for a specific bug, behavior that would
  surprise a reader. If removing the comment wouldn't confuse a
  future reader, don't write it.
- **Cwd is not a stable path.** Defaults that the proxy daemon
  reads should be absolute (e.g. `/etc/trollbridge/`,
  `/var/log/trollbridge/`), not cwd-relative. The codebase paid
  three rounds of bugs (#14, #19) for ignoring this rule.
- **Two distinct hosts in trollbridge's deployment model.** The
  *proxy host* runs `trollbridge run` and owns the CA private key
  + audit log + LLM API key file. The *consumer host* runs apps
  that proxy through and owns a copy of the CA's public cert.
  Code that defaults file paths must pick a side and stay on it;
  do not assume the operator running a CLI command is on the proxy
  host.
- **Per-job artifacts under `jobs/<id>/`** when working on this
  repo via the GO.md workflow. trollbridge is a public repo, so
  job artifacts go in the operator's private workspace
  (`/src/dan/jobs/`), not in this tree.
- **Releases via `scripts/release.sh`.** Never tag manually; the
  script edits version-bearing files (README, server.go), promotes
  `CHANGELOG.md` `## Unreleased` to a versioned heading, commits,
  tags, builds the four-arch matrix, pushes, and publishes the GH
  release in one go. `--bump patch|minor|major --yes` for
  non-interactive. The script preflights that `## Unreleased` is
  non-empty and refuses to release otherwise — see the CHANGELOG
  convention below.
- **CHANGELOG.md `## Unreleased` is part of the working tree, not an
  afterthought.** Every change an operator would notice — a new flag,
  a wire-protocol shift, a behavior change, the closing of a tracked
  issue — adds a one-line entry under the right subsection of
  `## Unreleased` (Wire / TUI / Operator / Forensics / Docs) **in
  the same commit that lands the change**. At release time
  `scripts/release.sh` consumes that section as the GH release
  body via `gh release create --notes-file`, so the discipline at
  commit time directly determines how the release reads to a
  visitor. Internal-only refactors, test-only changes, and
  dependency bumps with no behavior delta do not earn an entry.
  Issue numbers are cited as `(#NNN)` in the entry; reference the
  audit-log fields or wire codes by name so an operator searching
  for `event=startup_failure` lands on the matching entry.
- **Daemon-mode runs use `--no-console`.** `trollbridge run
  --no-console` suppresses the operator UI and is the deployment
  shape for systemd / supervisor / container hosts. Approvals are
  driven from another host via `trollbridge attach` or auto-resolved
  by `approvals.timeout_seconds` / `approvals.signal_after_seconds`.
  The `event=startup install_mode=daemon …` line names the run mode
  for log-tailing operators.
- **Manual approve / deny decisions persist.** Pressing `a` / `d` in
  the operator UI (or POSTing to `/v1/holds/<id>/approve|deny` over
  the mTLS control plane) writes the request's URL pattern to
  `lists.allow` / `lists.deny` in `trollbridge.yaml` and re-parses
  the lists in-process. `event=allowlist_added` / `event=denylist_added`
  fire at INFO; `event=list_persist_failure` at WARN on write failure.
  Wired at the queue layer (`Queue.SetDecisionPersist`) so both
  in-process TUI and attach-mode go through the same hook.

## Common producer workflows

- **Add a CLI subcommand.** Add `cmd/trollbridge/<name>.go` with a
  `new<Name>Cmd() *cobra.Command`. Register in `root.go`'s
  `cmd.AddCommand(...)` block under the right group (`groupOperate`,
  `groupConfigure`, `groupAudit`, `groupCA`).
- **Add a rule effect.** Add a const to `internal/types` (e.g.
  `EffectFooBar`), parse it in `internal/policy/rule.go`, handle it
  in `internal/server/server.go`'s effect switch (search for
  `case types.EffectAllow` to find the dispatch). Update the test
  fixtures in `internal/server/`.
- **Touch the wire contract.** Edit `internal/server/refusal.go`,
  ensure both server.go and intercept.go pick up the change via
  `statusFromEffect`, and update the contract guard test
  `TestDenyResponse_NoReasonOnTheWire`. Update `DESIGN.md` §5.6
  AND `PROXY-SETUP-AGENT.md` AND `CLIENT-SETUP-AGENT.md` AND `PROXIED-AGENT.md` (downstream consumers
  decode by these constants).
- **Touch the YAML schema.** Update `internal/config/config.go`
  struct, the `defaultConfigYAML` template in
  `cmd/trollbridge/init.go`, and `config.example.yaml`. Keep all
  three in sync — drift breaks the operator's authoring surface.

## Things to avoid

- Cwd-relative path defaults for files the daemon will read.
- Conflating proxy-host and consumer-host operations.
- Inlining CA bootstrap into `trollbridge init` (init must not
  require root; CA generation is a separate `trollbridge ca init`
  step on the proxy host).
- Disclosing the deny reason on the wire (audit log only, keyed
  by request_id).
- Treating build breaks as one-shot fixes instead of jobs (see
  GO.md if working under that workflow).

## Hard-won constraints

Each of these has cost a defect, a reopen, or a release. Grouped by the area they fire in.

- **Init writes only what the day-one operator runs.** When adding a feature whose default config requires no operator action (identities, rule files, redaction recipes, etc.), the *engine* support is independent from the *init template*. Default to keeping the init template minimal — operators add the section when they need it; the example yaml documents the schema for discovery. Exception: if the feature is mandatory for the proxy to work at all, it belongs in the default. Reason: every default is a per-operator tax, and "advertised surface that doesn't work end-to-end" extends to "advertised surface that does nothing."
- **Touching `cmd/trollbridge/init.go` triggers an audit of agent-facing init docs.** Any change to what `init` writes (file count, file names, default sections in the generated YAML, cobra `Short` string) requires re-grepping `AGENTS.md`, `README.md`, and `DESIGN.md` for "init writes", "writes N files", and the names of any artifacts that may have been added or removed. The doc and the code have no other coupling; the audit is the only thing that prevents drift.
- **Schema migrations require a doc sweep in the same commit.** When a config-file format changes — keys renamed, file layout migrated to inline structures, defaults trimmed — `DESIGN.md`, `AGENTS.md`, and `README.md` sections that named the old shape become wrong. The post-merge review must include a `grep` over each for the old shape's keywords; any hit is a drift defect to fix in the migration commit, not a follow-up.
- **A feature implemented but not documented is a partial ship.** When adding a new pattern grammar, syntax, or input-format extension, the same commit that lands the code MUST update `DESIGN.md` and `config.example.yaml`. A grep for the new syntax in `DESIGN.md` is the post-condition.
- **Advertised features need in-binary activation help.** When trollbridge documents a setting that requires non-trivial operator action to activate (TLS interception → install the CA into client trust stores; mTLS controller → issue + install operator client cert), the binary MUST surface the activation steps. Pointing operators at `DESIGN.md` or external docs is the failure shape "advertised surface that doesn't work end-to-end" exists to prevent.
- **Client-facing signal quality is part of the product contract for an agent-egress proxy.** When changing a response shape that an automated client consumes (deny envelope, error body, header set), prefer registered standards (RFC 9209 `Proxy-Status`, structured-fields per RFC 8941) over custom headers, and surface the same correlation id (`request_id`) in both the audit log and the response — every client failure should be one grep away from its full audit trail.
- **Proxy-generated 4xx/5xx responses MUST set `Connection: close`.** A proxy-generated error is not a candidate for connection reuse — the proxy's connection state is decoupled from the upstream's, and the next request on the same connection would race the proxy's shutdown bookkeeping. Verify on the wire (raw TCP dial + `http.ReadResponse`), not just in tests that use a high-level client.
- **Proxy host vs consumer host distinction.** Trollbridge runs on a *proxy host* and is configured by an operator there; its clients (curl, agents, IDEs) run on *consumer hosts* that may be different machines. CA cert paths in the operator's config must be canonical, machine-portable values (e.g. under `~/.trollbridge/ca/`) — not cwd-relative — because the cert install step happens on the consumer host with no relationship to where the operator was when they ran `init`. Same logic applies to LLM key paths, audit-log paths, and any other artifact path the operator might run from a different cwd than the trollbridge process.
- **`trollbridge run` config-not-found error must name `trollbridge init` as the next step.** The advertised CLI surface (`trollbridge run`) gives a generic file-not-found error when the operator hasn't sequenced `init` yet — that is the "advertised feature without activation help" shape. Wrap the `os.IsNotExist` case in `internal/config`'s loader.
- **Any TUI/proxy slice produced from a Go `map` is sorted before exposing to the UI, and indexed selections track by stable ID — not by slice index.** Go map iteration order is randomized per process; a TUI row list, queue selector, or completions panel that materializes a `map` into a slice without a deterministic sort produces a different row order each render. Indexed selection that survives a re-sort (cursor "row 3" persisted across renders) breaks: row 3 is a different request. The two-part rule: (a) sort the materialized slice by a stable key — request id, hostname, started-at timestamp; (b) when persisting a selection across renders, store the row's stable ID and re-resolve to the current index on each render.
- **Activation-surface help text (`cmd/trollbridge/*.go` cobra `Long`/`Short` strings, `doctor`/`init`/`update` output, command-line examples in error messages) triggers a doc-drift sweep over `README.md`, `AGENTS.md`, and `DESIGN.md` in the same commit.** Extension of the existing `cmd/trollbridge/init.go`-triggers-audit rule: any change to user-facing activation strings in `cmd/trollbridge/*.go` is the same shape — duplicated strings across code + docs with no other coupling. The grep is the only thing that prevents drift. Sweep keywords are the changed verb/noun plus any hard-coded URL or pipeline (`| bash`, `curl -fsSL`, etc.).
- **`// Mirrors the …` comments are deferred-refactor markers — when a change touches one mirror, audit the others in the same commit.** A `// Mirrors the X in package Y` comment is a code-review-time confession of duplicated structure; it survives review by promising "we'll extract this later." When a bug or feature touches one mirror, the audit step is `git grep -i "mirrors the"` across the repo; for each hit, decide whether the duplicate is still load-bearing (different layering constraints) or whether the change is the right moment to extract. If the touched change is non-trivial, extract — don't add a third mirror.
- **When adding a request-handling path that parallels an existing one (handleHTTP ↔ handleConnect ↔ intercept), the design phase enumerates the lifecycle calls (`s.ops.Begin`, `transitionOpFromEvaluating`, `s.ops.HoldPending`, `s.ops.Resolve`) and confirms the new path calls each one the existing path calls, in the same order.** Missing any of these makes that request class invisible in the ops ring — the operator's TUI/`/v1/ops` view never sees those requests at all. The check is a side-by-side enumeration during `Itemize`, not a code-review-time guess.
- **OS-coupled code uses build-tagged helper files (`{name}_{unix,windows}.go`) over runtime `runtime.GOOS` branches.** Pattern already in use for `ca_paths_*`, `ca_install_candidates_*`, `keymode_*`. Runtime `if runtime.GOOS == "windows"` branches compile on both OSes but don't surface the divergence to reviewers (or to `go vet`); the cross-compile lane treats them as live on every OS, even the one the branch doesn't run on. Build-tagged files give each OS its own concrete code path, fail loudly when an OS-specific symbol is missing, and let `git grep` over one file show the full per-OS surface.
- **New YAML struct-decode sites use the strict-decode helper, never raw `yaml.Unmarshal` / bare `yaml.NewDecoder`.** Once `internal/yamlx.DecodeStrict` (or the equivalent helper) is in place, every new decode site routes through it; the helper encapsulates `KnownFields(true)`, the `io.EOF`-guarded first `Decode`, and the trailing-document drain check. Raw `yaml.Unmarshal` silently accepts unknown keys and silently drops trailing documents — the class trollbridge's strict-decoding work exists to prevent. Review-time grep: `git grep -nE 'yaml\.(Unmarshal|NewDecoder)' -- '*.go' ':!internal/yamlx/*'`; every hit outside the helper package is a defect.
- **Schema-migration doc sweep includes loader docstrings and package docs, not only `DESIGN.md`/`AGENTS.md`/`README.md`.** When a config schema migrates (keys renamed, sections inlined, defaults trimmed), the audit set extends to: the loader function's docstring, the loader package's package-level doc, any "config file format" prose in `internal/config/doc.go` or sibling. These rot in the same way `DESIGN.md` does, but are missed by `*.md`-only greps. Sweep keyword: the *old* schema's terms plus `Load`, `Parse`, `Decode` in the loader package.
- **Substring assertions on "error message names key K" use a K that is not a substring of a real field name.** `mod` is a substring of `mode`, `model`, `modifiers`; `addr` is a substring of `address`. A substring-grep assertion `strings.Contains(err.Error(), "mod")` passes against an error message that names *any* of those longer fields, satisfying the assertion while exercising the wrong code path. Use a fixture key the production code does not carry (`priorty` — typo of `priority` — works reliably, or any 6+ char string the codebase doesn't otherwise emit).
- **`internal/selfdescribe/drift_test.go` is load-bearing — embedded-doc edits go through `cp` from the source.** Trollbridge embeds several agent-facing markdown docs (`AGENTS.md`, `SETUP-AGENT.md`, `CLIENT-SETUP-AGENT.md`, etc.) into `internal/selfdescribe/` for `trollbridge describe` to serve. The drift test fails when the embedded copy diverges from the source and prints the exact `cp` command to recover. After editing any source doc that has an embedded counterpart, the same commit runs the drift test (`go test ./internal/selfdescribe/...`) and applies the printed `cp` if it fires.
- **Lint that rejects `_ = m.<field>` placeholders inside `Match`/`Rule` evaluators in `internal/policy/`.** Same class as #123's strict-decoding (advertised clause does nothing): a field declared on `Match` that is read into a placeholder in the evaluator looks loaded but is never matched on. Custom `go vet`-style check or a `reflect`-based test that asserts every `Match` struct field appears as a load-bearing reference in the matcher's `matches` body (not just `_ = m.X`).
- **Wrong-reason-passing-test class has recurred on this codebase three times — coverage audits re-scan their own added tests.** The 167 audit re-introduced the same shape under a "0 patterns found" verdict because the post-audit suite was not re-scanned against the pre-audit patterns. Trollbridge-side discipline: any `gh issue close` for a test-coverage audit on this repo waits until the audit has re-grepped the *committed* added tests for: `assert.True(t, true)` after a no-op call, satisfiability shapes ("X happens when Y" assertions that pass with Y absent), HTTP 400 assertions without code-field pinning.
- **README and user-facing-doc simplification follows the CTA pattern from `TROLLBRIDGE_DESIGN.md`, not an audience-spine framing.** Four rounds of README simplification (#70, #93, #135/177, TB-10/180) with audience-spine framings ("who is this for? what do they need to know?") consistently produced "meandering" shapes the user rejected and re-asked. The shape the user accepts is the CTA-led pattern: *Try it / Have an agent set it up / Read how it works* — three calls-to-action with terminal commands, agent setup link, and design doc link in that order. New README rewrites start from that skeleton, not from an audience analysis. Three prior CI gates and deferral triggers did not prevent the recurrence; structural framing was the load-bearing fix. **Trigger for the next simplification pass: recurrence-count, not line-count.** When a job classifies its own work as "README too long / meandering / doesn't lead with CTAs" — or when a user comment re-files the same class — that is itself the signal to do a structural rewrite, not to file yet another deferral.
- **"Show X at the bottom" UI changes pair ordering with windowing in the same commit.** Sorting pending/recent rows to the tail of a list only helps when the list fits on screen; without a scroll-offset that keeps the tail visible, the user sees the same head rows as before and the change appears to do nothing. The pairing is mandatory: any "show X at the bottom" / "sort to tail" change ships with the windowing/scroll-anchor change that makes the new order visible. The recurrence-shape (#156 added the sort; #175 added the window months later) is what this rule prevents.
- **Mutations that persist to config YAML reload via `srv.Cfg()` on EVERY persist path — not just the named one.** Trollbridge's allow/deny/declined lists are read through the cfg getter; the suggestion engine, the matcher, and the audit-render path all dereference through it. A persist path that writes the YAML but doesn't reload the cfg leaves the in-memory matcher stale until the next process restart. The recurrence-shape: Accept reloaded; Decline did not (#183→#188). Persist paths in trollbridge: Accept, Decline, Add (manual edit), Remove (manual edit), Revert (undo). Each must call the same reload primitive. This is the trollbridge-specific instance of the global multi-representation-mutation rule.
- **Generalize detectors enumerate the full granularity ladder; the scorer picks broader-when-justified-by-traffic, narrower-when-not.** Detection and scoring are separate phases. Detection enumerates every applicable granularity (exact host, host/path-prefix, host/*, scheme://host/*, *.domain) — never just the narrowest. The scorer then picks the broadest level that *the observed traffic justifies*: if 80%+ of observed paths under `host` cluster into a small subset (e.g. `host/api/*`), prefer the narrower allow; surface `host/*` only when traffic breadth across the host is even. The two failure shapes this prevents: (a) detection-narrow-only hides the broader opportunity (the 225 fix); (b) detection-broad-always overshoots and offers `host/*` when the operator only needs `host/api/*`. Test shape: one fixture with even-breadth traffic must surface `host/*`; one with concentrated-subset traffic must surface the narrower allow.
- **Error-sentinel checks (`errors.Is(err, ErrXYZ)`) must hold on EVERY `Client` implementation that returns the sentinel — HTTP path AND in-process path, mock AND real.** When a reducer or controller gates behavior on `errors.Is(err, ErrAlreadyApproved)` (or similar), every concrete `Client` impl must wrap returned errors so the check fires on both paths. A reducer that works against the HTTP-mediated client but no-ops against the in-process client is the canonical partial-fix shape — both paths reach the same reducer code but one returns the sentinel wrapped and the other returns the bare error. Sweep technique on any new sentinel: `git grep -nE 'errors.Is\(.*Err[A-Z]'` then audit each `Client` impl that calls into the matching surface.
- **Raw-mode TUI goroutines need an explicit shutdown `context.Context` — Ctrl-C is a stdin byte, not a signal.** Once the terminal is in raw mode, the kernel does not translate `^C` into `SIGINT`; the byte arrives as `\x03` on stdin and must be handled by the TUI's input loop, not by `signal.NotifyContext`. Every long-lived TUI goroutine (queue subscriber, advisor poller, log tailer) must accept a `ctx context.Context` cancelled by the TUI's shutdown path, and the TUI's input loop must call the cancel func on `\x03` and on `q`/quit. The failure shape: the user presses Ctrl-C, the screen redraws, background goroutines keep running, the process exits only when the queue blocks.
- **Render cells that may carry ANSI escapes are sized with `visibleLen`/`padRightVisible`, never `runeTrunc` or `%-*s` byte-width padding.** Color codes, blink, and modifiers are bytes that both rune-count and byte-count treat as content; an ANSI-bearing cell sized by `runeTrunc(cell, w)` renders narrower than `w` visible columns and displaces every sibling cell on the row, corrupting the panel. A `+N byte buffer` hack that compensates at one callsite is fragile — it fails the moment upstream ANSI overhead grows past the buffer (a new color wrap, a reversal indicator). The structural fix is visible-width math owning all sizing; drop the buffer. Sweep on any new colorized cell: `git grep -n 'runeTrunc('` and confirm no argument is ANSI-bearing; replace colorized callsites with `padRightVisible` (or a `visibleTrunc` if true truncation is needed).
- **Adding a `tui.Options` field requires auditing EVERY `RunOperator(` callsite — `run`, `quickstart`, `attach` — not just the one the directive named.** The TUI is launched from multiple binaries/entrypoints; a new option wired only in `cmd/trollbridge/run.go` leaves `quickstart.go` and `attach.go` at the zero value, so the feature works in one launcher and silently no-ops in the others. Quickstart is the recommended onboarding path — exactly where an operator first tries a new feature, and exactly where the gap is most visible. Sweep technique: `git grep -n 'RunOperator(' cmd/trollbridge/` and wire the new option in every launcher that should carry it (default-zero is acceptable only when deliberately chosen). This is the trollbridge instance of the global "Apply to all consumers" / multiple-binary-launcher shape.
- **Cursor-affinity / `preserveSelection` work must include a "drain-to-empty → re-arrival" cross-tick test, not only steady-state.** A within-tick affinity fix (cursor stays in its region when *some* members of that region remain) leaves the cross-tick case uncovered: the cursor's preferred region drains to empty in one tick and a new member arrives a later tick. Tests whose fixtures always keep a representative in the region never exercise the latch-across-empty path, and the gap ships as a reopen. Companion implementation rule: latch the affinity flag (`wasOnPending`/`CursorPreferPending`) BEFORE the tick's clamp mutates the cursor off the region — a post-clamp capture reads the already-moved state and never sets the flag.
- **Every numbered principle in `docs/alignment-principles.md` carries a code-citation line and a code-side enforcer test in the same commit that adds the principle.** A principle codified *after* the violating code path shipped does not surface the existing violation — the document is aspirational while the code is non-compliant. The pairing makes drift impossible: the principle's text names the enforcing test (`Enforced at <file>:<fn>; test <file>`), and the test's comment names the principle; a future violation goes red in CI rather than accumulating silently. When adding or auditing a principle, find its load-bearing code path and add a test that fails if the principle is violated; layering invariants (e.g. `internal/advisor` must not reach `internal/configwrite`) are enforceable as an AST/`reflect` check.
- **Line-positioned terminal writes (`\x1b[<r>;1H<line>\x1b[K`) strip the trailing `\r` from each line first.** `strings.Split(frame, "\n")` leaves a `\r` on each entry; the `\r` returns the cursor to column 0 *before* `\x1b[K` fires, wiping the line just written — a delta renderer that doesn't strip it blanks the TUI after the first frame. Companion to the `visibleLen` ANSI-width rule.
- **Classify a failure at the layer that knows its origin, not by re-deriving the class from error text downstream.** The updater path misclassified download failures (404, timeout) and bash-missing because the class was inferred from the error string at a downstream hint-rendering site instead of recorded where the error arose. Classify download errors as `FailureNetwork` at the call site; detect bash-missing via `errors.Is(err, exec.ErrNotFound)` where the exec is attempted. Downstream "report this" hints that re-derive the class from text misdirect the operator.
- **Adding a `DecisionSource` (or any cross-package enum) touches sweep sites in more than one package — run `go test ./...`, not just the touched package, before commit.** A new `DecisionSource` value must update two `internal/types` enum tables AND the `internal/audit` level-filter test's admit-set; the audit sweep test is load-bearing and only fails if the whole-module suite runs. Full-suite-before-commit surfaces swept consumers a single-package run misses.
- **Intercept-path tests must assert the held request carries `scheme=https-intercepted` to prove the intercept code ran — not the bare CONNECT from the outer handler.** A test that allows CONNECT to a host and then holds "the request" can hold the outer CONNECT (exercising the wrong handler) and still pass, giving false confidence the intercept path works. Idiom: allow CONNECT to the host, hold the inner request by path/criterion, assert the held request's scheme is `https-intercepted`.
- **Exported test-double counters read from another goroutine are concurrent state — make them `atomic.Int64`/mutex-guarded from the start.** A mock provider's call counter read off a concurrent goroutine is a data race even though it's "just a test"; the `-race` lane catches it, but the discipline avoids the red.