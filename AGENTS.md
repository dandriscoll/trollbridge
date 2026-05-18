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
