# Client setup agent — pointing your egress at trollbridge

You are an agent (or a script driven by one) that has been given the
address of a running trollbridge proxy and asked to **route your own
HTTP/HTTPS egress through it**. This file is the consumer-side
bootstrap — small, copy-pasteable, and usually fetched directly from
the proxy itself.

(If you are instead the agent **installing** trollbridge for the
first time on a host, you want `PROXY-SETUP-AGENT.md`. If you are
the LLM whose runtime egress goes through the proxy and you need
the wire-contract prompt, you want `PROXIED-AGENT.md`.)

## Inputs you should already have

- The proxy's listen address (e.g. `127.0.0.1:8080`).
- Optional: whether TLS interception is on. If unsure, fetch
  `/setup/ca.crt` (below); a 200 means yes, a 404 means no.

## Step 1 — Set the proxy environment variables

Pick the scope that matches your use case. **Shell-wide** routes
every later command in this shell through trollbridge — convenient
but persistent. **Per-process** routes only the agent and its
children — precise but must be repeated for each invocation.

### Option A — Shell-wide (every process in this shell)

For most HTTP clients on Linux/macOS/Windows-WSL:

```sh
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTPS_PROXY"
unset NO_PROXY no_proxy
```

`trollbridge env -c <config>` (run on the proxy host) prints the
exact lines for the configured listen address.

### Option B — Per-process / agent-scoped (only the agent and its children)

When you don't want to pollute the operator's interactive shell —
for example, an LLM agent, a CI step, or a sandboxed automation
that should route its own egress through trollbridge but leave
unrelated commands untouched — prefix the agent's launch command
with the env vars instead of exporting them:

```sh
HTTPS_PROXY=http://127.0.0.1:8080 \
HTTP_PROXY=http://127.0.0.1:8080 \
https_proxy=http://127.0.0.1:8080 \
http_proxy=http://127.0.0.1:8080 \
NO_PROXY="" no_proxy="" \
  <agent-binary> <args…>
```

Equivalent using `env(1)` (clearer when the command line is long):

```sh
env HTTPS_PROXY=http://127.0.0.1:8080 \
    HTTP_PROXY=http://127.0.0.1:8080 \
    https_proxy=http://127.0.0.1:8080 \
    http_proxy=http://127.0.0.1:8080 \
    NO_PROXY="" no_proxy="" \
    <agent-binary> <args…>
```

Windows PowerShell — set `$env:…` in a child scope so the change
does not survive the spawned process tree:

```powershell
& {
  $env:HTTPS_PROXY = "http://127.0.0.1:8080"
  $env:HTTP_PROXY  = "http://127.0.0.1:8080"
  $env:NO_PROXY    = ""
  & <agent-binary> <args…>
}
```

The agent and every child it spawns inherit `HTTPS_PROXY` /
`HTTP_PROXY`. Once the agent exits, the operator's shell is
unchanged — no later `curl`, `git`, or `apt` call goes through
trollbridge unless that invocation is itself prefixed.

## Step 2 — Fetch the proxy's self-description (recommended)

Once the env vars are set, the proxy can introduce itself:

```sh
curl http://config.trollbridge.dev/setup            # index
curl http://config.trollbridge.dev/setup/proxied-agent.md
curl http://config.trollbridge.dev/setup/instructions.md   # this file
curl http://config.trollbridge.dev/setup/ca.crt    # if TLS interception is on
curl http://config.trollbridge.dev/setup/env       # shell exports
```

The `Host: config.trollbridge.dev` header tells the proxy "serve
your own metadata, do not forward this." DNS for that name is
intentionally a sinkhole — these endpoints only work *through* the
proxy.

## Step 3 — Install the CA cert (only if TLS interception is on)

If `/setup/ca.crt` returns 200, the proxy is doing TLS interception
and your client must trust the proxy's CA before HTTPS calls will
succeed.

```sh
# Linux (system trust store):
curl -o /tmp/trollbridge-ca.crt http://config.trollbridge.dev/setup/ca.crt
sudo install -m 0644 /tmp/trollbridge-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# macOS:
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/trollbridge-ca.crt
```

For language runtimes that bring their own trust bundle (Python's
`certifi`, Node's `NODE_EXTRA_CA_CERTS`, Java's `cacerts`, etc.),
also point those at the cert file. The repo's main README has
runtime-specific snippets.

## Step 4 — Verify

```sh
curl -sI https://example.com
# Expect: HTTP/2 200 (or whatever example.com normally returns).

curl -sI https://blocked.example.com
# Expect: HTTP/1.1 470 (declined) or 471 (held for approval).
# If you see 470/471, the proxy is in-path and enforcing policy.
```

If you get a TLS error on a normally-allowed host, the CA cert is
not yet installed in your client's trust store.

## Step 5 — Read the runtime contract

If you are an LLM agent, the system prompt your operator should
load is `PROXIED-AGENT.md` — fetch it from the proxy:

```sh
curl http://config.trollbridge.dev/setup/proxied-agent.md
```

That file describes status codes 470/471, the
`Trollbridge-Request-Id` header, and the rules for how to behave
when the proxy declines or holds a request.

## Day-to-day

You will not normally re-fetch any of the above after Step 4. Cache
the CA cert next to your other client config; quote
`Trollbridge-Request-Id` to the operator when you need to ask
about a specific request.
