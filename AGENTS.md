# AGENTS.md

Instructions for an LLM-driven coding agent (Claude Code, Cursor,
Aider, OpenAI Codex, or similar) that has been asked by its user
to set up and run trollbridge.

This file is **for the agent, not the human**. The human's quickstart
is [`README.md`](./README.md). The full spec is [`DESIGN.md`](./DESIGN.md).
Topology recipes are [`docs/deploy.md`](./docs/deploy.md). The
annotated config reference is [`config.example.yaml`](./config.example.yaml).

## What trollbridge is, in one paragraph

Trollbridge is an HTTP/HTTPS proxy that gates an agent's network
egress against a deterministic policy, with optional LLM-advisor
classification on the gaps. The agent (you) sends requests through
it; the proxy decides allow / deny / hold-for-approval and writes
every decision to a JSON-lines audit log. Trollbridge is only
effective when the host firewall blocks every other network path —
the proxy is the *only* way out. See `docs/deploy.md` for the
firewall posture per topology.

## Read this before configuring anything

- **Do not pick silently.** The user has goals; you do not know them
  until you ask. Topology, policy posture, advisor on/off, advisor
  provider, TLS interception — every one of these is a load-bearing
  choice. Ask first, configure second.
- **Never put credentials in the YAML.** The advisor's `api_key_path`
  is a *file path*, not the key itself. Write the key into a
  separate file (`chmod 600`) and put the path in the config.
- **The advisor cannot mutate lists.** Only humans can edit
  `allow.txt` / `deny.txt`. You may suggest edits to the user; you
  may not write them yourself when the system is running under the
  advisor's identity.
- **TLS interception needs user action.** If the user wants HTTPS
  body inspection, they must install `trollbridge-ca.crt` into the
  client's trust store. You cannot do this from inside the agent.
  Surface it as a step the user runs.
- **Public repo.** This file ships in a public OSS repo. Do not paste
  internal hostnames, real API keys, real private network ranges, or
  user PII into it under any circumstance.

## Step 0 — Ask the user

Before running any command, get answers to these. Skipping any of
them produces a configuration the user did not ask for.

1. **Where will the agent run relative to trollbridge?** `local`
   (same host as the proxy), `local-vm` (a VM on the same host;
   reaches the proxy across a bridge), or `remote` (a different
   machine). The choice drives the proxy's bind address. See
   `docs/deploy.md` for the per-environment recipes (laptop, Incus
   VM, sidecar, system daemon) that map onto these presets.
2. **What is the agent's goal?** Pick one or more from the catalog
   in *Goal mapping* below. The user's words ("block exfiltration",
   "let CI fetch npm and nothing else", "I want to review every new
   destination") map to specific knobs.
3. **Should the LLM advisor be on?** It only fires on `ask_llm` rules
   or in `default-ask` mode. It cannot elevate above the
   deterministic policy. If on, get the provider and the model
   string. For `aoai` or `other` providers, also get the endpoint
   URL (`init` will ask). The API key file is written next to
   `trollbridge.yaml` (`<config-dir>/llm.key`, mode 0600).
4. **Should TLS be intercepted?** Without interception, trollbridge
   sees only `host:port` for HTTPS — path, method, header, and body
   rules cannot fire. Default off; turn on only if the user accepts
   installing a CA cert into the client's trust store.
5. **Where will the audit log live?** Default `/var/log/trollbridge/`
   on system installs, `~/.trollbridge/` for laptop use. The user
   may want it elsewhere (a dedicated volume, a syslog forwarder).

Write the answers somewhere the user can see them before you start
configuring — chat is fine, a scratch file is better.

## Step 1 — Build

```sh
make build
./bin/trollbridge --help
./bin/trollbridge version
```

`make build` produces a static `bin/trollbridge` (CGO disabled).
Verify `--help` lists the commands you expect: `run`, `init`,
`validate`, `decisions`, `logs`, `rules`, `approve`, `deny`,
`sessions`, `selftest`, `ca`, `version`.

## Step 2 — Initialize a config tree

For laptop use, just run:

```sh
./bin/trollbridge init
```

`init` defaults its target directory to the current working directory
— `./trollbridge.yaml`. Every other subcommand reads from the same
default, so `trollbridge doctor`, `trollbridge run`, etc., all find
the config without `-c` when run from the same directory. trollbridge
is a deployed proxy, not a user application; its config lives with
the deployment, not under `~/.config`.

For a system install, set `TROLLBRIDGE_CONFIG=/etc/trollbridge/trollbridge.yaml`
(an explicit operator override, used by the systemd unit in
`packaging/systemd/`) and pass `-d /etc/trollbridge` to `init`. The
env var continues to short-circuit the cwd default for every
subcommand.

When stdin is a TTY, `init` runs as a guided setup that asks the
operator about topology, mode, TLS interception, and the LLM
advisor — and (when interception is chosen) generates the CA in
the same invocation. The questions match the Step-0 list above;
the user does not need to repeat themselves to you. Sit on the
side and let `init` collect the answers directly.

When stdin is not a TTY (CI, redirected input) or the operator
passes `--non-interactive`, `init` writes the static default
config without prompting. The default config is a single annotated
`trollbridge.yaml` (a copy of `config.example.yaml`; every key is
annotated). Allow / deny patterns live inline under `lists:` and
are mutated in place when the operator types `allow X` / `deny X`
in the console. Advanced features — `identities:` and structured
rule files via `policy.include:` — are not in the default; add
them when you need time windows, identity scoping, body patterns,
or `ask_user` / `ask_llm` effects.

## Step 3 — Set policy posture

Edit `trollbridge.yaml`'s `mode:` to one of:

- **`default-deny`** — only allow rules forward. Everything else
  (including everything not in `allow.txt`) is denied. Pick this when
  the user said *"block by default"*, *"least-privileged egress"*, or
  *"only let it reach what I list"*.
- **`default-allow`** — only deny rules block. Pick this when the
  user said *"audit but don't block"*, *"let it reach the internet
  but log everything"*. Audit-log review is the primary control.
- **`default-ask`** — unmatched requests are held for advisor or
  operator review. Pick this when the user said *"I want to review
  every request"* or *"surface anything new for me"*. The advisor
  needs to be on (Step 5) for this to be tractable; otherwise every
  unmatched request blocks until a human approves it.

If unsure, ask the user. `default-deny` is a safe default for an
agent's first session if they cannot pick.

## Step 4 — Author allow/deny lists

Flat lists are the simple authoring surface. Reach for structured
rules in `rules.yaml` only when you need time windows, identity
scoping, body patterns, or `ask_llm` / `ask_user` effects.

**Flat list syntax** (`allow.txt`, `deny.txt`):

```
api.github.com           # exact host, any port
*.npmjs.org              # subdomain wildcard (does NOT match the apex)
host:443                 # exact port
host/api/*               # path prefix
host/exact               # exact path
*                        # any host (use sparingly)
```

Deny wins over allow. Each line is read literally; there is no
inheritance.

**Structured rule shape** (`rules.yaml`, see
[`rules/base.example.yaml`](./rules/base.example.yaml)):

```yaml
- id: ask-on-mutating-github
  description: POST/PUT to GitHub require operator approval.
  priority: 300
  match:
    identity: coding-agent
    host: api.github.com
    method: ["POST", "PUT", "PATCH", "DELETE"]
  effect: ask_user
```

First match wins; ties broken by priority (higher first), then
declared order. Effects: `allow | deny | ask_user | ask_llm`.

### Goal mapping

Map the user's stated goal to concrete knobs:

| user said…                                              | knobs                                                                                          |
|---------------------------------------------------------|------------------------------------------------------------------------------------------------|
| "block exfiltration"                                    | `mode: default-deny`. Curated `deny.txt` (cloud metadata, pastebins). `allow.txt` minimal.     |
| "let CI fetch npm and pypi and nothing else"            | `mode: default-deny`. `allow.txt` lists `registry.npmjs.org`, `*.npmjs.org`, `pypi.org`, `files.pythonhosted.org`. Empty advisor. |
| "review every new destination"                          | `mode: default-ask` + advisor on. Curated `deny.txt`. `allow.txt` for the few hosts the user is sure about. |
| "audit but don't block"                                 | `mode: default-allow`. Strict `deny.txt` (metadata, exfil destinations). Advisor off.          |
| "different agents have different permissions"           | Define `identities:` (mTLS / bearer / source IP). Use structured rules with `match.identity:`. |
| "the agent shouldn't be able to read response bodies of secret-bearing endpoints" | `redaction.body_redactors:` (jsonpath / regex). See `config.example.yaml`. |

If the user names a host the catalog does not cover, ask whether
they want it on the allow list, the deny list, or held for advisor
review the first time it shows up.

## Step 5 — Configure the LLM advisor (optional)

Skip this step if the user said the advisor should be off. Otherwise
edit the `llm:` block in `trollbridge.yaml`:

```yaml
llm:
  enabled: true
  provider: anthropic                      # named provider, or any HTTP endpoint
  model: claude-opus-4-7                   # or another model the provider serves
  endpoint: https://api.anthropic.com
  api_key_path: /etc/trollbridge/llm.key    # FILE path, not the key
  timeout_seconds: 8
  cache_ttl_seconds: 300
  send_body: false                         # never send bodies by default
  on_unavailable: ask_user                 # ask_user | deny | allow
  confidence_floor: medium                 # below this, fall back to ask_user
```

Then write the API key into the file you named:

```sh
umask 077
printf '%s' "$ANTHROPIC_API_KEY" > /etc/trollbridge/llm.key
chmod 600 /etc/trollbridge/llm.key
```

Do not echo the key into your chat history.

**Provider choice.** Two named providers control the auth header:
- `anthropic` (default) → `Authorization: Bearer <api_key>`
- `aoai` (Azure OpenAI) → `api-key: <api_key>`

Other strings fall back to generic Bearer with a startup warning.
The wire payload (DESIGN.md §9 — a JSON object with `effect`,
`confidence`, `reason`, optional `modifiers`, `scope`,
`suggested_rule`) is fixed across providers; point `endpoint:` at a
wrapper that speaks it.

**Verify the LLM connection** with `trollbridge doctor -c <path>`
before the first `trollbridge run`: it loads the YAML, parses the
rules and lists, and dispatches a synthetic classification call
against the configured provider. Any mismatched endpoint, bad key,
or misnamed provider surfaces as a `FAIL: …` line with a non-zero
exit, instead of being a silent degradation at runtime.

**Failure modes the user should know:**

- Advisor offline → behavior is `on_unavailable`. `ask_user` is the
  safe default; `deny` fails closed; `allow` fails *open* and is
  rarely what the user wants.
- Advisor returns confidence below `confidence_floor` → fallback to
  `ask_user`.
- Advisor proposes a modifier the binary doesn't recognize → the
  modifier is dropped silently; the rest of the decision still
  applies.
- Advisor cannot elevate. If the deterministic policy says deny, no
  advisor recommendation overrides it.

## Step 6 — TLS interception (optional)

Skip if the user did not opt in. Otherwise:

```sh
./bin/trollbridge ca init                # writes trollbridge-ca.{crt,key}
./bin/trollbridge ca export --out trollbridge-ca.crt
```

Then **the user** installs `trollbridge-ca.crt` into the client's
trust store (OS-level, language runtime, browser — depends on what
will run through the proxy). You cannot do this from inside the
agent. Tell the user the exact path and ask them to confirm before
flipping the switch.

In `trollbridge.yaml`:

```yaml
interception:
  enabled: true
  ca:
    cert_path: /etc/trollbridge/trollbridge-ca.crt
    key_path:  /etc/trollbridge/trollbridge-ca.key
  passthrough_hosts:
    - "*.googleapis.com"
    - "login.microsoftonline.com"
```

Add to `passthrough_hosts` any service the user knows pins certs
(banking, some Google services, Apple's push infrastructure).
Without interception, HTTPS rules can only match on host and port.

## Step 7 — Validate

```sh
./bin/trollbridge validate -c ~/.trollbridge/trollbridge.yaml
```

Report any error to the user verbatim. Do not silence and re-try.
Common errors: a referenced rule file is missing, an `api_key_path`
file does not exist, a TLS interception block is enabled without
the CA files in place.

## Step 8 — Run and verify

```sh
./bin/trollbridge run -c ~/.trollbridge/trollbridge.yaml
```

It prints the listen address. Now in another shell, exercise the
policy with the user watching:

```sh
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080

# allow path: should succeed
curl -sI https://api.github.com/zen

# deny path: should be refused at the proxy
curl -sI https://pastebin.com/ || true

# (if mode is default-ask) ask path: should hold for approval
curl -sI https://example.com/ || true
```

Then in a third shell:

```sh
./bin/trollbridge logs tail --follow
```

The user should see one decision per request, with effect, identity,
host, and reason. If they don't, the proxy is not seeing the
request — re-check the client's HTTPS_PROXY env var and the host
firewall.

## What the client sees on a refusal

Every response from trollbridge — allow forwarding, decline, hold
for approval, CONNECT establishment — carries
`Trollbridge-Request-Id: <uuid>`, which matches the audit log's
`request_id`. On a refusal, the response also carries:

- **Status code 470** when the proxy actively declined the request,
  or **471** when the request is held for approval. Both codes are
  unassigned in the IANA HTTP Status Code registry, by design: a
  caller that sees 470 or 471 — even through an HTTP library that
  hides the response body — can infer the response came from
  trollbridge, not the upstream service. Trollbridge never emits
  `403` or `511` for a policy outcome.
- `Proxy-Status: trollbridge; error=http_request_denied; request-id="<uuid>"`
  (RFC 9209). The `details=` parameter is intentionally absent — the
  reason text is not on the wire.
- `Trollbridge-Reason: declined` (or `pending`). The header value is
  always the categorical effect token; reason text is not on the
  wire.
- A plain-text body
  `trollbridge: request <declined|pending> (request_id=<uuid>)`, or
  a JSON body `{effect, request_id}` when the client sent
  `Accept: application/json`.

The reason and rule id are deliberately **not** disclosed on the
wire. They live in the audit log, keyed by `request_id`. An operator
handed a request id by an agent can grep the audit log directly:

```sh
grep '<uuid>' ~/.trollbridge/trollbridge.audit.jsonl | jq .
```

**CONNECT-decline opacity.** When the proxy declines a CONNECT (the
common case for HTTPS without TLS interception), trollbridge writes
the 470 status + headers + body to the wire — but most HTTP client
libraries (curl's libcurl, Python `httpx`/`urllib3`/`requests`,
Node `https`) discard the proxy's response shape on tunnel failure
and surface a generic "tunnel connect failed" error to the
application. The signal is on the wire (verifiable with `openssl
s_client -connect` or a raw TCP dial), but the agent code may not
see it. Tell the user to grep the audit log when "agent says
network is broken" and the destination was an HTTPS host: the
audit log carries the same `request_id` even when the agent's
client-library hides the response.

## Step 9 — Hand back to the user

Tell the user the four day-to-day commands:

- `trollbridge logs tail --follow` — live audit log.
- `trollbridge decisions --since 1h` — recent decisions in summary.
- `trollbridge approve <hold-id> [--scope once|session|rule]` —
  resolve a held request as approved; the scope flag controls
  whether the decision is one-shot, lasts the session, or becomes a
  saved rule.
- `trollbridge deny <hold-id> [--reason "…"]` — resolve a held
  request as denied; the reason lands in the audit log.
- The interactive console — when `trollbridge run` is run on a
  terminal (TTY), it offers a `trollbridge>` prompt for
  `allow <pattern>` / `deny <pattern>` / `remove <pattern>` /
  `list [allow|deny]`. Edits go to the first configured allow / deny
  file and the file watcher reloads within ~1 second.

If `approvals.control_listen` is non-localhost the operator must
enable bearer-token auth on the control plane. The CLI subcommands
(`approve`, `deny`, `sessions`, `rules reload`) do not yet accept a
`--bearer-token` flag — operators wrap with `curl` against the
control plane API in that case. (Tracked.)

## Optional — Topology-specific notes

Read `docs/deploy.md` before doing any of these and ask the user
which topology they chose in Step 0.

- **Incus VM** — `packaging/incus/cloud-init.yaml` provisions a VM
  with trollbridge running and the firewall locked to "egress only
  via the host bridge IP". Run `trollbridge selftest --from-vm` to
  verify the VM cannot reach the internet except through the proxy.
- **Sidecar container** — `packaging/docker/Dockerfile` builds a
  static image. Compose it on a network with `internal: true` so the
  sidecar is the only egress path. Mount the CA cert; set
  `HTTPS_PROXY` in the agent container.
- **Systemd host daemon** — `packaging/systemd/trollbridge.service`
  runs as a non-root user with `/etc/trollbridge/` as the config
  root. `journalctl -u trollbridge` for the operational log.
- **Firewall snippets** — `packaging/firewall/` has `nftables.conf`
  and `iptables.sh`. The proxy is only as strong as the firewall;
  if the agent has any other path out, the policy doesn't bind.

## Tell the user what they got

When you finish, summarise (in chat, briefly):

1. Topology chosen and where trollbridge is running.
2. Mode and the high-level policy ("default-deny with an allow list
   of N hosts" or "default-ask with the advisor on").
3. Whether TLS interception is on, and if so, whether the CA cert is
   installed in the client trust store.
4. Whether the LLM advisor is on, which provider, which model, and
   what `on_unavailable` is set to.
5. Where the audit log lives.
6. The four day-to-day commands above.

Do not assume the user remembers the choices they made earlier in
the conversation — write the summary as if they are seeing it for
the first time.
