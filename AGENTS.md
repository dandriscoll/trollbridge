# AGENTS.md

Instructions for an LLM-driven coding agent working **on the
trollbridge codebase** — building, testing, refactoring, fixing
bugs.

If you are a different kind of agent, you want a different file:

- An agent **setting up trollbridge for a user** (running `init`,
  configuring policy, generating the CA): see
  [`SETUP-AGENT.md`](SETUP-AGENT.md).
- An agent whose own HTTP/HTTPS egress **goes through trollbridge**
  (you are calling out to the network and the proxy sits in front
  of you): see [`PROXIED-AGENT.md`](PROXIED-AGENT.md).

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
internal/configwrite/   # in-place yaml.v3 Node-API edits (console-pane writes)
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
make vet
make tidy
```

The binary embeds its version via ldflags (`-X
github.com/dandriscoll/trollbridge/internal/server.Version=…`).
`make build` derives the version from `git describe`; release
builds use the script.

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
  script edits version-bearing files (README, server.go), commits,
  tags, builds the four-arch matrix, pushes, and publishes the GH
  release in one go. `--bump patch|minor|major --yes` for
  non-interactive.

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
  AND `SETUP-AGENT.md` AND `PROXIED-AGENT.md` (downstream consumers
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
