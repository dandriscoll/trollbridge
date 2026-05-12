# Anthropic LLM-setup agent — wiring Anthropic into trollbridge

You are an LLM-driven coding agent (Claude Code, Cursor, Aider,
OpenAI Codex, or similar) that has been asked by your user to
**configure trollbridge to use Anthropic as its LLM advisor**.
This file is self-contained and copy-pasteable.

If you are instead setting up the trollbridge proxy host from
scratch, read `PROXY-SETUP-AGENT.md` first; that file covers
build/init/run and refers you back here for the LLM-advisor step.

If the user wants Azure OpenAI instead of Anthropic, read
`AZURE-OPENAI-LLM-SETUP-AGENT.md`.

## What this file gets you

A working LLM advisor for trollbridge, classifying the requests
the deterministic policy did not cover. Concretely:

- A non-empty `llm.key` file on the proxy host with the user's
  Anthropic API key, mode `0600`.
- An `llm:` block in `trollbridge.yaml` set to:
  `enabled: true`, `provider: anthropic`, `model: <a current
  Claude model>`, `endpoint:
  https://api.anthropic.com/v1/messages`, `api_key_path: <path
  matching the file you wrote>`.
- A passing `trollbridge doctor` invocation that verifies the wire
  is up end-to-end.

The advisor is *advisory*: it never elevates a deterministic deny
to an allow, never mutates allow/deny lists, never learns the
proxy's name or role. See `docs/alignment-principles.md`.

## Two distinct hosts — read this first

trollbridge has two distinct hosts in the general case:

- The **proxy host** runs `trollbridge run`. It owns the CA
  private key, the audit log, and the LLM API key file
  (`/etc/trollbridge/llm.key` in daemon mode).
- The **consumer host** is any machine routing its egress through
  the proxy.

This file is **proxy-host-only**: the api key is consumed by the
daemon when it dispatches advisor calls. If the operator running
this snippet is not on the proxy host, the snippet's "write the
key" step has to happen elsewhere — surface that to the user
explicitly, do not paper over it.

In `local` topology the proxy host and the operator's host are
the same. In `local-vm` and `remote` they differ. Confirm before
proceeding.

## Step 0 — Ask the user

Do not pick silently. Surface these questions and get answers
before writing anything:

1. **Install mode.** Is trollbridge running in user mode (single
   operator's home directory; key at `<init-dir>/llm.key`) or
   daemon mode (systemd-managed; key at
   `/etc/trollbridge/llm.key`)? Defer to `trollbridge init`'s
   prior answer if there is one — re-asking is fine, guessing is
   not.

2. **Topology.** Is the operator running this snippet on the
   proxy host? If not, the "write the key file" step happens on
   the proxy host, not here. Tell the user.

3. **Do they have an Anthropic API key already?** If yes, ask
   them to keep it ready (do not paste it into chat). If no,
   walk through the console step below.

4. **Which Claude model do they want to use?** The default
   trollbridge ships with is `claude-opus-4-7`. Smaller/faster
   options that still support tool calls: `claude-sonnet-4-6`,
   `claude-haiku-4-5`. The advisor will work with any current
   Claude model that supports the structured tool-call protocol.

## Step 1 — Get an Anthropic API key

**You cannot create an Anthropic API key programmatically from
inside this agent.** Anthropic API keys come from the Anthropic
Console; surface it as a user step.

Tell the user:

1. Open https://console.anthropic.com/ and sign in.
2. Navigate to *Settings → API Keys*.
3. Create a new key (or copy an existing one). Anthropic shows
   the key value **once** on creation; have the user store it
   somewhere safe.
4. The key looks like `sk-ant-…`. The string is the value the
   trollbridge daemon will use as `x-api-key`.

If the user does not have an Anthropic account or billing set
up, that is a separate, console-only flow. Surface it; do not
proceed until they have a key in hand.

## Step 2 — Write the key file

The api key goes into a **file**, never into the YAML. The
daemon reads it at startup.

Path:

- **Daemon mode:** `/etc/trollbridge/llm.key` (canonical;
  cross-machine stable).
- **User mode:** `<trollbridge.yaml directory>/llm.key`. Use
  whatever directory holds the user's `trollbridge.yaml`.

Write securely (no shell history of the key, no echo into your
own chat history):

```sh
# Daemon mode — needs root because /etc/trollbridge is owned by the trollbridge user.
sudo install -m 600 /dev/stdin /etc/trollbridge/llm.key <<'KEY'
sk-ant-…
KEY
```

```sh
# User mode — non-root, same directory as trollbridge.yaml.
umask 077
printf '%s' "$ANTHROPIC_API_KEY" > ./llm.key
chmod 600 ./llm.key
```

**Do not echo the key into chat.** Have the user paste it into
their own shell. If they paste it to you instead, do not write
it to a file inside the agent: surface the shell command and
ask them to run it.

**Verify the file:**

```sh
ls -l /etc/trollbridge/llm.key      # daemon mode
# or
ls -l ./llm.key                     # user mode
```

The size should be a non-zero number of bytes; the mode column
should read `-rw-------` (or `0600`).

## Step 3 — Wire the YAML

You have two paths. **Pick Path A unless the user has already
run `trollbridge init` and only wants to add the LLM section
now.**

### Path A — Use `trollbridge init`

```sh
trollbridge init -d <directory>
```

When the interactive flow asks "Enable the LLM advisor?", answer
**yes**, then:

- Provider: `anthropic`
- Model: the Claude model from Step 0 (e.g., `claude-opus-4-7`)
- Endpoint: accept the default (`https://api.anthropic.com/v1/messages`)
- API key path: accept the default

`init` writes the resolved `llm:` block into `trollbridge.yaml`
for you.

In daemon mode `init` does **not** write the key file — that's
Step 2 above. In user mode `init` *will* prompt for the key on
stdin and write it inline; if you already did Step 2, point the
existing path and decline the inline prompt.

### Path B — Edit `trollbridge.yaml` directly

If the user has a `trollbridge.yaml` already and only wants to
add or update the LLM section, edit it to include:

```yaml
llm:
  enabled: true
  provider: anthropic
  model: claude-opus-4-7
  endpoint: https://api.anthropic.com/v1/messages
  api_key_path: /etc/trollbridge/llm.key
  timeout_seconds: 8
  cache_ttl_seconds: 300
  send_body: false
  on_unavailable: ask_user
  confidence_floor: medium
```

In user mode, change `api_key_path` to the path matching Step 2
(e.g., `./llm.key` or an absolute path to the same file).

`on_unavailable: ask_user` is the safe default. `deny` fails
closed; `allow` fails *open* and is rarely what the operator
wants. Leave `medium` as the confidence floor; the advisor falls
back to `ask_user` below that.

## Step 4 — Verify

Run trollbridge doctor against the YAML you just wrote:

```sh
trollbridge doctor -c /path/to/trollbridge.yaml
```

If `llm.enabled` is `true`, doctor sends a synthetic
classification call to Anthropic and checks the wire and schema.
Expected output:

```
trollbridge doctor:
  config:   OK (...)
  rules:    OK (...)
  lists:    OK (...)
  llm:      contacting provider=anthropic endpoint=https://api.anthropic.com/v1/messages auth=x-api-key (timeout 8s)
  llm:      OK (provider=anthropic, endpoint=..., auth=x-api-key, effect=allow, confidence=high)
```

If `llm.enabled: false` in the YAML but the user wants to
verify the wiring *before* flipping the switch, add
`--check-llm`:

```sh
trollbridge doctor -c /path/to/trollbridge.yaml --check-llm
```

`--check-llm` runs the LLM step regardless of the YAML flag —
useful for pre-flight verification while keeping production
config untouched.

### Failure modes the user should know

doctor classifies failures by **layer** so the next action is
obvious. Pattern-match on the FAIL line:

- `FAIL: api_key_path "X" does not exist or is unreadable: ...`
  → The key file at path X is missing, a directory, or
  unreadable by the doctor process. Re-do Step 2. Common cause
  in daemon mode: `sudo` was omitted and the file landed in the
  wrong owner. `ls -l X` will show the truth.
- `FAIL: ... layer=wire err=anthropic http 401: {"error":...}`
  → The key is rejected by Anthropic. Either the key is invalid
  (re-fetch from the console), or it's a key from a different
  account, or it was rotated.
- `FAIL: ... layer=wire err=dial tcp: connection refused`
  → The proxy host cannot reach `api.anthropic.com`. Check
  egress firewall rules on the proxy host. If trollbridge is
  itself running through another HTTP proxy, ensure
  `HTTPS_PROXY` is honoured by the trollbridge binary's HTTP
  client (it is).
- `FAIL: ... layer=wire err=anthropic http 4xx/5xx ...`
  → Endpoint URL is wrong, or Anthropic is having an outage.
  Re-check the endpoint (default should be
  `https://api.anthropic.com/v1/messages`).
- `FAIL: ... layer=schema err=anthropic response had no tool_use block ...`
  → The configured model returned text instead of a structured
  tool call. Either the model does not support tool use, or the
  prompt was overridden. Pick a current model that supports
  tools (Opus 4.x, Sonnet 4.x, Haiku 4.x).
- `FAIL: ... layer=unknown err=...`
  → Catch-all. Re-run with `--verbose` to see connection-level
  events; if still unclear, paste the doctor output into a
  trollbridge issue.

## Step 5 — Hand back to the user

Tell them:

- `trollbridge doctor` is green; the LLM advisor is wired.
- To activate the advisor, ensure `llm.enabled: true` in
  `trollbridge.yaml` and either restart `trollbridge run` or
  let the hot-reload pick up the YAML edit (closes #80).
- The deterministic policy still runs first; the advisor only
  fires on `ask_llm` rules or when `mode: default-ask` is set.
  If they configured the advisor but never see it consulted,
  check `mode:` and the rule set.
- To watch advisor activity in real time, open the TUI's LLM
  panel: in `trollbridge run`, press `3`.

## Guardrails for you, the agent

- **Never write the user's API key into this chat.** Have them
  paste it into their own shell and run the file-write command
  there.
- **Never commit the key file.** The path goes into YAML; the
  file itself is operator-managed and outside the repo.
- **Do not invent provider strings.** The named providers are
  `anthropic` and `aoai`. Anything else falls back to generic
  Bearer with a startup warning — and is not what this snippet
  targets.
- **Do not change the wire-format settings.** `send_body:
  false` is the default; flipping it makes trollbridge forward
  request bodies to the advisor, which is a privacy decision
  the operator owns. Surface it; do not flip it on their
  behalf.
- **Do not promise things the LLM advisor cannot do.** It does
  not write allow/deny lists. It does not learn the proxy's
  name or role. It does not override a deterministic deny.
