<p align="center">
  <img src="trollbridge_icon.png" alt="trollbridge logo" width="160">
</p>

# trollbridge

![trollbridge — LLM-Powered Proxy & Security Gateway for AI Agents](trollbridge_infographic.png)

An LLM-powered HTTP/HTTPS proxy that lets LLM agents reach network
resources under controlled, inspectable, policy-governed conditions.

The proxy is implemented in Go: a single static binary, no runtime
deps.

- [`DESIGN.md`](DESIGN.md) — full design document.
- [`AGENTS.md`](AGENTS.md) — for coding agents working *on* the
  trollbridge codebase (build, test, conventions).
- [`PROXY-SETUP-AGENT.md`](PROXY-SETUP-AGENT.md) — self-contained
  instructions for an agent **installing** the trollbridge proxy
  on a host.
- [`CLIENT-SETUP-AGENT.md`](CLIENT-SETUP-AGENT.md) — self-contained
  instructions for an agent **pointing its own egress** at a
  running trollbridge (also fetchable from the running proxy at
  `http://config.trollbridge.dev/setup/instructions.md`).
- [`PROXIED-AGENT.md`](PROXIED-AGENT.md) — self-contained
  system-prompt fragment for an agent whose egress **goes through**
  trollbridge.
- [`docs/deploy.md`](docs/deploy.md) — deployment recipes.
- [`config.example.yaml`](config.example.yaml) — annotated config;
  the simple authoring surface lives inline as `lists.allow` /
  `lists.deny`.
- [`rules/base.example.yaml`](rules/base.example.yaml) —
  structured rules (for the advanced cases).
- [`packaging/`](packaging/) — systemd unit, Dockerfile, Incus
  cloud-init, firewall snippets.

## Install

```sh
curl -fsSL https://trollbridge.dev/install.sh | sh
```

The script picks the right tarball for your OS and arch, verifies the
release's SHA256SUMS, and installs `trollbridge` to `/usr/local/bin`.
Run `trollbridge version` to confirm.

### Verify and install manually

Pre-built binaries for Linux and macOS (amd64 and arm64) are
attached to each tagged release on the
[releases page](https://github.com/dandriscoll/trollbridge/releases).

```sh
curl -L -o trollbridge.tar.gz \
  https://github.com/dandriscoll/trollbridge/releases/download/v0.7.6/trollbridge_v0.7.6_linux_amd64.tar.gz
# Verify against the release's SHA256SUMS file before extracting.
tar -xzf trollbridge.tar.gz
sudo install -m 0755 trollbridge_v0.7.6_linux_amd64/trollbridge /usr/local/bin/trollbridge
trollbridge version
```

## Build from source

Requires Go 1.26+.

```sh
git clone https://github.com/dandriscoll/trollbridge.git
cd trollbridge
make build

# Fastest path (user-mode, no controller, no TLS interception):
./bin/trollbridge quickstart   # writes a minimal yaml + starts the proxy

# Or the full setup (interactive — picks user-mode or daemon-mode, then runs):
./bin/trollbridge init         # interactive in a TTY; default config otherwise
./bin/trollbridge run          # listens on 127.0.0.1:8080
```

When `run` starts on a terminal, it prints a copy-pasteable
"try this next" banner naming the listen address and the
quickest test recipe.

In another shell, send a request through the proxy:

```sh
trollbridge test https://example.com
# or, for any HTTP client in this shell:
eval "$(trollbridge env)" && curl -sI https://example.com
```

`trollbridge env` reads the listen address from `trollbridge.yaml`
in the current directory and emits upper- and lowercase
`HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` exports.

For verbose per-request operational output, run with `--verbose`,
`--log-level=debug`, or `TROLLBRIDGE_LOG_LEVEL=debug`. Operational
lines carry a `request_id=` field that correlates with the audit
log.

## Operator UI

When `trollbridge run` starts on a terminal, it draws a two-pane
operator UI in the alt-screen: the upper pane lists pending holds
(approve / deny in real time), and the lower pane is the operator
console (`allow`, `deny`, `remove`, `list`, `reload`, `test`,
`doctor`, `help`, `quit`). Each pane has its own rounded box-drawing
chrome — the focused pane is rendered in bright cyan, the unfocused
in dim grey. Per-pane keybindings live in the bottom border of each
pane; the `[Tab] focus <pane>` cue lives in the focused pane's top
border at top-right; the `[Ctrl-C] quit` cue lives in the console
pane's bottom border at bottom-left. There is no separate hint row —
every help string is adjacent to the surface it changes.

Keys:

- `Tab` — switch focus between the approvals pane and the console pane
- approvals pane: `a` approve · `d` deny · `↑↓` (or `j`/`k`) select · `r` refresh now · `q` (or `Esc`) quit
- console pane: type a command, `Enter` to run, `Backspace` to edit, `Ctrl-U` to clear the line, `Esc` to return to the approvals pane
- anywhere: `Ctrl-C` quit

The approvals list refreshes automatically as the queue changes;
one-shot `trollbridge approve <id>` / `trollbridge deny <id>` remain
available for scripted use.

Manual approve / deny decisions are **sticky**: pressing `a` writes
the request's URL pattern to `lists.allow` in `trollbridge.yaml`
(and pressing `d` writes to `lists.deny`), then re-loads the lists
in-process so the next request to the same URL matches the rule and
skips the queue (closes #49). The pattern is the request's full URL
today (`https://api.example.com:443/path` for HTTP, `host:port` for
CONNECT); LLM-driven generalization is planned. To approve once
without persisting, edit the YAML by hand or use the typed REPL
`allow <pattern>` for a more general match.

The TUI assumes a UTF-8 terminal; on `LANG=C` or environments without
box-drawing rune support, run with `--no-console` (see *Daemon mode*
below).

To drive the same UI from another terminal — over the daemon's mTLS
control plane — run:

```sh
trollbridge attach -c ~/.trollbridge/trollbridge.yaml
```

In `attach`, the approvals pane is fully functional; list editing,
test, and doctor commands stay on the proxy host (the console pane
prints a one-line "not available in attach mode" hint).

### Daemon mode

Pass `--no-console` to `trollbridge run` to suppress the operator UI.
The proxy listens, accepts requests, holds approvals, and writes the
operational log as in the interactive case — only the TUI is omitted.
Approvals can be driven from another host via `trollbridge attach`,
or auto-resolved by `approvals.timeout_seconds` (default-deny on
timeout) and `approvals.signal_after_seconds` (471 hold-signal to the
consumer at the configured cutoff). On startup the proxy emits one
INFO line — `event=startup install_mode=daemon ui=none default_decision=… approvals=in-process on_timeout=… [attach_endpoint=…]` —
naming the install mode for log-tailing operators.

## Self-describing endpoints

Once `trollbridge run` is up, an agent that has only the proxy's
address can fetch everything else it needs to bootstrap from the
proxy itself. The proxy intercepts requests where
`Host: config.trollbridge.dev` and serves bundled assets instead
of forwarding:

```sh
# With HTTP_PROXY=http://<proxy-host>:<port> set:
curl http://config.trollbridge.dev/setup                    # index
curl http://config.trollbridge.dev/setup/proxied-agent.md   # PROXIED-AGENT.md
curl http://config.trollbridge.dev/setup/instructions.md    # CLIENT-SETUP-AGENT.md
curl http://config.trollbridge.dev/setup/env                # shell exports
curl http://config.trollbridge.dev/setup/ca.crt             # CA cert (PEM); 404 if interception is off
curl http://config.trollbridge.dev/discovery                # JSON: wire protocol description (status codes, headers, body shapes)
```

Every 470 / 471 deny response also carries a `Trollbridge-Discovery`
header pointing at the discovery URL, so an agent that gets denied
can fetch the protocol document on the next request without prior
configuration.

`config.trollbridge.dev` is intentionally DNS-sinkholed — these
endpoints work *only* through the proxy, so a misconfigured client
that drops `HTTP_PROXY` cannot accidentally reach a real host. The
endpoints are open (no auth); the CA cert is public-by-design.

## Configuration

`trollbridge.yaml` is organised around four operator decisions:

1. **per-surface bind** — each of `proxy:`, `control:`, `metrics:`
   is a single `<host>:<port>` string. Host aliases: `all` =
   `0.0.0.0`, `lo` = `127.0.0.1`. Bracket IPv6 literals
   (`[fd00::1]:8081`). Surfaces are independent, so the proxy
   can listen on `all:8080` while the control plane stays on
   `lo:8081`. `metrics: 0` disables the (unimplemented)
   Prometheus endpoint.
2. **`lists`** — inline `allow:` / `deny:` patterns. The console
   REPL writes back to trollbridge.yaml; comments outside `lists:`
   survive. Each entry is `[<METHOD>|*] [<scheme>://]host[:port][/path]`
   with an optional method prefix (e.g., `GET https://api.example.com/v1/*`)
   and `*` wildcards on host/path. Method-less entries match any
   method (backward-compatible with pre-method patterns).
3. **`llm`** — provider / model / endpoint / api-key. Provider
   selects the auth header and wire shape: `anthropic` (default)
   sends `x-api-key: …` with a pinned `anthropic-version` header
   (Anthropic Messages API); `aoai` (Azure OpenAI) sends
   `api-key: …` (chat-completions or Responses API, auto-selected
   from the endpoint URL).
4. **`llm.directives`** — inline multi-line system prompt for the
   advisor.

Run `trollbridge doctor -c <path>` after editing the YAML — it
loads the config, parses the rules and lists, and (when LLM is
enabled) issues a real classification call so misconfigured
endpoints / keys / providers fail loud before `trollbridge run`.

### Hosts

trollbridge has two distinct hosts in the general case:

- **proxy host** — runs `trollbridge run`. Owns the CA private key,
  the audit log, and `/etc/trollbridge/trollbridge-ca.{crt,key}`.
- **consumer host** — any machine running apps whose egress goes
  through the proxy. Owns a copy of the CA's *public* cert in its
  system trust store.

In `local` topology these are the same machine; in `local-vm` and
`remote` they are different. `trollbridge init` writes a yaml
(no privilege required) regardless of which host runs it; CA
generation and daemon launch are explicitly proxy-host steps.

### First-run ritual (on the proxy host, as root)

The control plane requires mTLS, signed by the same CA used for
TLS interception:

```sh
sudo trollbridge ca init                          # generates /etc/trollbridge/trollbridge-ca.{crt,key}
sudo trollbridge ca client-cert <op-name>         # mint your client cert
sudo mv <op-name>.crt ~/.trollbridge/controller-client.crt
sudo mv <op-name>.key ~/.trollbridge/controller-client.key
```

The CA always lives at `/etc/trollbridge/trollbridge-ca.{crt,key}` —
the canonical path is the same on every machine, so a config
shared across hosts works without per-host edits.

`trollbridge init` does not generate the CA. CA generation is the
separate `trollbridge ca init` step above; it requires root because
it writes to `/etc/trollbridge/`. The operator running `init` may
not be on the proxy host or may not own that directory.

The CLI auto-loads the cert/key from `~/.trollbridge/`; override with
`TROLLBRIDGE_CONTROLLER_CERT` / `TROLLBRIDGE_CONTROLLER_KEY`.

For TLS interception (separate from controller mTLS — same CA):

```sh
# Local install (run on the same host as `trollbridge run`):
trollbridge ca install --apply        # searches canonical paths;
                                      # requires root (sudo)

# Remote install (consumer app on a different host than the proxy):
#   1. From the trollbridge host:
#        scp trollbridge-ca.crt user@consumer:/usr/local/share/ca-certificates/
#   2. From the consumer host:
#        sudo trollbridge ca install --apply

# Then enable interception:
#   set interception.enabled: true in trollbridge.yaml
```

`trollbridge ca install` searches `/etc/trollbridge/trollbridge-ca.crt`
(the canonical default; cross-machine stable) and
`/usr/local/share/ca-certificates/trollbridge-ca.crt`. Pass
`--cert <path>` to override; the printed install commands always
use the absolute form so they paste cleanly into any shell or any
machine.

When `trollbridge run` is interactive, the operator UI's console
pane (Tab to focus) accepts live edits to `lists.allow` /
`lists.deny` in trollbridge.yaml:

```
trollbridge> allow api.github.com
added api.github.com to allow (3 entries total)
trollbridge> list allow
allow:
  127.0.0.1
  api.github.com
  localhost
(3 entries)
```

Mutations rewrite trollbridge.yaml in place; comments outside
the `lists:` subtree survive. The running daemon re-parses the
file after each mutation. List mutation is human-only — the
LLM advisor cannot modify `lists.allow` / `lists.deny`
under any circumstance. See `docs/alignment-principles.md` for
the four principles governing the LLM advisor's role.

See `docs/deploy.md` for deployment recipes and `DESIGN.md` for
the full specification.

## License

[MIT](LICENSE).
