# Azure OpenAI LLM-setup agent — wiring AOAI into trollbridge

You are an LLM-driven coding agent (Claude Code, Cursor, Aider,
OpenAI Codex, or similar) that has been asked by your user to
**configure trollbridge to use Azure OpenAI as its LLM advisor**.
This file is self-contained and copy-pasteable.

If you are setting up the trollbridge proxy host from scratch,
read `PROXY-SETUP-AGENT.md` first; that file covers
build/init/run and refers you back here for the LLM-advisor step.

If the user wants Anthropic instead of Azure OpenAI, read
`ANTHROPIC-LLM-SETUP-AGENT.md`.

## What this file gets you

A working LLM advisor for trollbridge, backed by Azure OpenAI:

- A non-empty `llm.key` file on the proxy host with the user's
  Azure OpenAI API key, mode `0600`.
- An `llm:` block in `trollbridge.yaml` set to:
  `enabled: true`, `provider: aoai`, `model:
  <deployment-name>`, an Azure-shaped `endpoint:`, and
  `api_key_path: <path matching the file>`.
- A passing `trollbridge doctor` invocation.

trollbridge's `provider: aoai` setting selects the Azure OpenAI
wire shape (`api-key` header, deployment in URL path or model
field depending on API). The advisor is *advisory*: it never
elevates a deterministic deny, never mutates lists, never learns
the proxy's name or role. See `docs/alignment-principles.md`.

## Two distinct hosts — read this first

Same model as the rest of trollbridge:

- **Proxy host** runs `trollbridge run`. Reads `llm.key`
  (`/etc/trollbridge/llm.key` in daemon mode).
- **Consumer host(s)** route egress through the proxy.

This snippet is **proxy-host-only**.

## Step 0 — Ask the user

Surface these questions; do not pick silently:

1. **Install mode.** Daemon or user mode? Determines the
   `llm.key` path.

2. **Topology.** Is the operator on the proxy host? If not, the
   key file gets written somewhere else.

3. **Does the user already have an Azure OpenAI resource?** If
   yes, get the **resource name**, **region**, and at least one
   **deployment name** from them. If no, walk through the portal
   provisioning below — *but* surface that provisioning incurs
   Azure costs and may require subscription admin approval (Azure
   OpenAI is a gated service).

4. **Which deployment to use?** In Azure OpenAI, a "deployment"
   pairs a model (e.g., `gpt-5.4`, `gpt-4o`) with a name the
   user picks. The **deployment name** is what trollbridge's
   `model:` field gets. The underlying model id is metadata; it
   does not appear in trollbridge's YAML.

5. **Chat-completions endpoint or Responses endpoint?**
   trollbridge supports both:
   - **Chat-completions** (older, widely deployed):
     `endpoint: https://<resource>.openai.azure.com/openai/deployments/<dep>/chat/completions?api-version=2024-10-21`.
     The deployment is in the URL path.
   - **Responses** (newer):
     `endpoint: https://<resource>.openai.azure.com/openai/responses?api-version=2025-04-01-preview`.
     The deployment is *not* in the URL; the `model:` field is
     load-bearing.

   If unsure, default to chat-completions — it's what most
   deployments target. trollbridge auto-detects which API to use
   from the endpoint URL; `trollbridge doctor` prints a hint if
   it had to normalise the endpoint.

## Step 1 — Provision (or confirm) the Azure resource

**You cannot create an Azure OpenAI resource from inside this
agent** unless the user has run `az login` and has a
permissions-equipped Azure CLI. Surface the steps; the user
takes them.

**If the user has an existing resource**, ask them to confirm:

```sh
az cognitiveservices account list --query "[?kind=='OpenAI'].{name:name,resourceGroup:resourceGroup,location:location}"
```

(requires `az login` and Azure CLI). Or in the portal:
*Cognitive services → Azure OpenAI*.

Capture: **resource name**, **resource group**, **region**.

**If the user does not have a resource**, the portal flow is:

1. Open the Azure portal at https://portal.azure.com.
2. Navigate to *Create a resource → AI + Machine Learning →
   Azure OpenAI*.
3. Pick a subscription, resource group, and region. Azure
   OpenAI availability varies by region; the user can check
   model availability at
   https://learn.microsoft.com/azure/ai-services/openai/concepts/models#standard-deployment-model-availability.
4. Submit; provisioning takes a couple of minutes.

Provisioning may be **gated**: Azure OpenAI requires the
subscription to have been approved. If the portal shows "request
access", surface that step to the user — it's a one-time form,
not something this snippet can bypass.

## Step 2 — Confirm or create a deployment

A resource is not enough; the user needs a **deployment** (the
named instance of a specific model).

Portal flow:

1. Open the AOAI resource.
2. Go to *Model deployments → Manage deployments*. This opens
   Azure AI Studio.
3. If no deployments exist, create one:
   - Pick a model (e.g., `gpt-5.4`, `gpt-4o`). For trollbridge,
     the model must support **function calling / tools** —
     non-tool-capable models will fail with a schema error in
     `trollbridge doctor`.
   - Pick a deployment name. **Write this down** — it goes
     into trollbridge's `model:` field. Common pattern: name
     the deployment after the model (`gpt-5.4`) for clarity.
4. If deployments exist, list their names and ask the user
   which one to use.

`az` alternative (read-only listing):

```sh
az cognitiveservices account deployment list \
  --name <resource> --resource-group <rg> \
  --query "[].{name:name,model:properties.model.name}"
```

## Step 3 — Get the API key

Portal flow:

1. Open the AOAI resource.
2. Go to *Keys and Endpoint*.
3. Copy either KEY 1 or KEY 2 (both work; the page exists so
   the user can rotate). Have them store it somewhere safe.

`az` alternative:

```sh
az cognitiveservices account keys list \
  --name <resource> --resource-group <rg> \
  --query key1 -o tsv
```

## Step 4 — Write the key file

Same as the Anthropic flow — the key goes into a file, never
into the YAML. The daemon reads it at startup.

Path:

- **Daemon mode:** `/etc/trollbridge/llm.key`.
- **User mode:** `<trollbridge.yaml directory>/llm.key`.

```sh
# Daemon mode.
sudo install -m 600 /dev/stdin /etc/trollbridge/llm.key <<'KEY'
<paste-the-azure-key>
KEY
```

```sh
# User mode.
umask 077
printf '%s' "$AZURE_OPENAI_API_KEY" > ./llm.key
chmod 600 ./llm.key
```

**Do not echo the key into chat.** Surface the shell command;
have the user run it.

Verify:

```sh
ls -l /etc/trollbridge/llm.key    # or ./llm.key
```

Mode `-rw-------`, non-zero size.

## Step 5 — Wire the YAML

Two paths; pick A unless the user already has a `trollbridge.yaml`.

### Path A — `trollbridge init`

```sh
trollbridge init -d <directory>
```

When the interactive flow asks "Enable the LLM advisor?",
answer **yes**, then:

- Provider: `aoai`
- Model: the **deployment name** from Step 2 (e.g., `gpt-5.4`,
  *not* the underlying model id).
- Endpoint: the URL from Step 0 question 5. For
  chat-completions:
  `https://<resource>.openai.azure.com/openai/deployments/<dep>/chat/completions?api-version=2024-10-21`.
  For Responses:
  `https://<resource>.openai.azure.com/openai/responses?api-version=2025-04-01-preview`.

### Path B — Edit `trollbridge.yaml` directly

```yaml
llm:
  enabled: true
  provider: aoai
  model: <deployment-name>       # NOT the underlying model id
  endpoint: https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=2024-10-21
  api_key_path: /etc/trollbridge/llm.key
  timeout_seconds: 8
  cache_ttl_seconds: 300
  send_body: false
  on_unavailable: ask_user
  confidence_floor: medium
```

Substitute `<resource>` and `<deployment>` with the user's
actual values. In user mode, set `api_key_path` to the path
matching Step 4 (e.g., `./llm.key`).

### Endpoint shape — frequent confusion

- The **resource name** is the unique Azure account name (e.g.,
  `acme-openai`). Goes in the leftmost subdomain of the URL.
- The **deployment name** is the operator-chosen instance name
  (e.g., `gpt-5.4`). For chat-completions, it appears in the
  URL path (`/openai/deployments/<dep>/...`) **and** in the
  `model:` field. For Responses, it appears *only* in the
  `model:` field; the URL path is `/openai/responses`.
- The **underlying model id** (e.g., `gpt-5.4`) is metadata in
  Azure; it does *not* appear in trollbridge's YAML.

If the user copy-pastes a URL from the Azure portal that
doesn't quite match either shape, `trollbridge doctor` runs a
normaliser that rewrites bare-resource URLs to a Responses-style
default and adds the `api-version` if missing. Look for `note:
endpoint normalised from … to …` in doctor's stderr.

## Step 6 — Verify

```sh
trollbridge doctor -c /path/to/trollbridge.yaml
```

Expected:

```
trollbridge doctor:
  config:   OK (...)
  rules:    OK (...)
  lists:    OK (...)
  llm:      contacting provider=aoai endpoint=https://acme-openai.openai.azure.com/... auth=api-key (timeout 8s)
  llm:      OK (provider=aoai, endpoint=..., auth=api-key, effect=allow, confidence=high)
```

If `llm.enabled: false` in YAML but you want to verify wiring
before flipping the switch:

```sh
trollbridge doctor -c /path/to/trollbridge.yaml --check-llm
```

### Failure modes the user should know

- `FAIL: api_key_path "X" does not exist or is unreadable: ...`
  → Re-do Step 4. Check the file path and permissions.
- `FAIL: ... layer=wire err=aoai http 401: ...`
  → Wrong key, or the key is for a different resource. Verify
  with `az cognitiveservices account keys list` or the portal.
- `FAIL: ... layer=wire err=aoai http 404: ...`
  → Endpoint URL is wrong. Most common: deployment name in the
  URL does not match a real deployment. Verify in the portal /
  with `az cognitiveservices account deployment list`.
- `FAIL: ... layer=wire err=dial tcp: ...`
  → The proxy host cannot reach `<resource>.openai.azure.com`.
  Check firewall rules.
- `FAIL: ... layer=schema err=... no tool ...`
  → The deployment's model does not support function calling.
  Pick a tool-capable model (most current Azure-hosted models
  do; some older preview models do not).
- `note: endpoint normalised from "X" to "Y"` (on stderr, not
  a FAIL)
  → trollbridge rewrote the URL into a canonical shape. Usually
  benign; if "Y" surprises the operator, write the canonical
  form explicitly in the YAML.
- `warning: unrecognized llm.provider "X"; falling back to anthropic translator`
  → Provider is misspelled. Must be exactly `aoai` (lowercase).

## Step 7 — Hand back to the user

- doctor is green; the advisor is wired against Azure OpenAI.
- Restart `trollbridge run` or let hot-reload pick up the YAML
  edit.
- The deterministic policy still runs first; the advisor fires
  only on `ask_llm` rules or `mode: default-ask`.
- TUI's LLM panel (`3` in `trollbridge run`) shows real-time
  advisor activity.

## Guardrails for you, the agent

- **Never write the user's API key into chat.** Surface the
  shell command; let them run it.
- **Never commit the key file.**
- **Never run `az` write commands** (`account create`,
  `deployment create`, etc.) without explicit user
  confirmation per command — these incur cost and may need
  subscription-admin approval.
- **Do not invent provider strings.** Exactly `aoai`.
- **Do not promise things the advisor cannot do.** It does not
  write allow/deny lists, does not learn the proxy's name or
  role, does not override deterministic deny.
