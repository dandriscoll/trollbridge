# llmtest — trollbridge LLM-advisor regression framework

`llmtest` lets you verify that trollbridge's LLM advisor is
implementing your policy in accordance with prompts and
expectations. It runs **live** LLM calls against fixture bundles
and asserts on the returned verdict (`allow` / `deny` / `ask_user`)
and confidence (`low` / `medium` / `high`).

Use it to catch:

- prompt-wording regressions (your system prompt loses its edge),
- model-version drift (the LLM behind your endpoint changed),
- subtle policy gaps (a host you thought was allowed lands as
  ask_user with low confidence).

The framework lives behind a `llmtest` build tag so the default
`go test ./...` does not pay LLM cost.

## Quickstart

```sh
# point at a working trollbridge.yaml (llm.enabled=true)
export TROLLBRIDGE_LLM_TEST_CONFIG=/etc/trollbridge/trollbridge.yaml

# run all bundles under llmtest/bundles/
make llm-test
```

Each bundle becomes a Go subtest. Each case in a bundle dispatches
one LLM call. Failures print:

```
FAIL  denylisted-host-get: verdict mismatch: got "ask_user", want "deny"
       (reason="unfamiliar host", confidence="medium")
```

Without `TROLLBRIDGE_LLM_TEST_CONFIG`, the suite skips with a hint.

## Bundle format

A bundle is a YAML file under `llmtest/bundles/*.yaml`:

```yaml
name: baseline
description: short one-liner

directives: |
  System prompt the LLM sees. Goes verbatim into the
  advisor.Input.Directives field — identical to cfg.llm.directives
  in your trollbridge.yaml.

lists:
  allow:
    - GET https://api.github.com/repos/*
  deny:
    - "*://malicious.example.com/*"

cases:
  - name: github-list
    request:
      method: GET
      host: api.github.com
      path: /repos/foo/bar
      # optional: scheme (default https), port (auto), headers, body_summary, identity
    expect:
      verdict: allow              # required: allow | deny | ask_user
      min_confidence: medium      # optional: low | medium | high
      max_confidence: high        # optional: low | medium | high
```

Required fields:
- `bundle.name`
- at least one `case`
- per case: `name`, `request.method`, `request.host`,
  `expect.verdict`.

Unknown YAML keys are rejected at load time (strict decoding).

## Expectation patterns

| Goal | Expectation |
|---|---|
| MUST allow with HIGH confidence | `verdict: allow, min_confidence: high` |
| MUST deny | `verdict: deny, min_confidence: high` |
| MAY allow but expect uncertainty | `verdict: allow, max_confidence: medium` |
| Genuinely ambiguous | `verdict: ask_user, max_confidence: medium` |

`min_confidence` / `max_confidence` define an inclusive band:
`min=medium max=high` passes for medium OR high; `min=high`
passes only for high.

## Starter bundles

- `baseline.yaml` — common-case allow patterns (github / openai /
  anthropic read paths).
- `security.yaml` — explicit-deny patterns and obvious-malicious
  shapes. The advisor should land deny + HIGH confidence here.
- `grey-area.yaml` — ambiguous requests. The advisor should land
  ask_user with at-most-medium confidence.

Add your own — drop a YAML file under `llmtest/bundles/` and it
joins the next `make llm-test` run automatically.

## How it relates to the rest of the test suite

- `go test ./...` (no tag): the framework's own logic (bundle
  loading, expectation comparison) gets covered by
  `bundle_test.go`. No LLM cost.
- `go test -tags=llmtest ./llmtest/...`: live LLM regression
  suite. Costs an LLM call per case. Gated.
- `go test -tags=e2e ./...`: e2e proxy-flow tests (#124). Separate
  lane from llmtest; they don't share fixtures.

## Notes

- The framework calls `advisor.Provider.Classify` directly,
  bypassing `advisor.Service`'s cache + digest layer. Each case
  is one fresh LLM call.
- Confidence values follow the advisor's existing vocabulary
  (low/medium/high). Numerical floats are not supported.
- Bundle directives and lists are passed into every per-case
  `advisor.Input` — they're context for the LLM, not policy
  the framework enforces locally.

Closes #133.
