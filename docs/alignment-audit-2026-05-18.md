# Alignment audit — 2026-05-18

One-time holistic audit per #140. Walks every field of the advisor's
input payload (`internal/advisor/advisor.go::Input`) and every
clause of the system prompt (`internal/advisor/prompts.go`) against
each of the five alignment principles in
[`docs/alignment-principles.md`](alignment-principles.md). Replaces
the principle-by-principle patches the project has done in prior
jobs (#118, #66, et al.) with a single sweep.

Verdict: **all five principles structurally clean** in trollbridge's
own code; two **soft concerns** under principle 4 where
operator-supplied input fields could leak host-application identity
if the operator names them descriptively. Each soft concern carries
a proposed fix; neither is shipped here — they are documentation /
review-pass changes that belong in a separate, scoped change set.

## Method

For each principle, walk:

1. **Input fields**: `Method`, `Scheme`, `Host`, `Port`, `Path`,
   `HeadersRedacted`, `BodySummary`, `Identity`, `Tool`,
   `RuleSetVersion`, `AllowList`, `DenyList`, `Directives`, `Mode`.
2. **Output fields**: `Effect`, `Scope`, `Reason`, `Modifiers`,
   `Confidence`, `Tool`.
3. **Prompt clauses**: every sentence of `baselineReview` and
   `baselineResearch`, plus `composeSystemPrompt`'s append behavior.
4. **Translator surfaces**: the tool name + tool definition shipped
   on the wire by `internal/advisor/{anthropic,aoai*}_translator.go`.

## Principle 1 — allow/deny list is human-only

**Verdict: clean.**

- `Output` has no list-mutation field. The closest neighbors —
  `Modifiers` (transformations), `Scope` (decision scope) — describe
  effects on the current decision, not list state.
- No advisor-package code imports `internal/configwrite`.
- No prompt clause asks the LLM for list edits.

## Principle 2 — LLM considers items not yet on the lists

**Verdict: clean.**

- `AllowList` / `DenyList` are framed in the prompt as evidence of
  operator intent ("treat them as evidence of operator intent for
  classifying this new, uncovered request").
- `consultAdvisorForHold` (the only advisor entry point) fires only
  after the engine returns `EffectAskUser` or `EffectAskLLM` — i.e.,
  only when the deterministic matcher has not produced a verdict.
- Confidence-floor downgrade in `Service.validate` widens the
  ask-user bar; the operator-config knob is `cfg.LLM.ConfidenceFloor`.

## Principle 3 — list interpretation is pixel-perfect

**Verdict: clean.**

- The prompt explicitly says "Do not attempt to re-match the lists
  yourself."
- No advisor-package call to `hostlist.Match`. No advisor-side
  pattern parsing.
- The advisor sees raw pattern strings (string slice), not parsed
  structures that would invite the LLM to reason about pattern
  semantics.

## Principle 4 — LLM does not learn what application it is advising

**Verdict: structurally clean in trollbridge's own code; two soft
concerns where operator-supplied input could leak app identity.**

### Clean surfaces

- `baselineReview` / `baselineResearch` prompts: "security policy
  classifier" framing; do not name trollbridge, "proxy," "gateway,"
  or "egress controller."
- Tool name across translators: `classify_request` — generic.
- `Method`, `Scheme`, `Host`, `Port`, `Path`, `HeadersRedacted`,
  `BodySummary`: request shape — leak no application metadata.
- `RuleSetVersion`: a hash, opaque.
- `Mode`: `"review"` / `"research"` — operating-mode descriptors,
  not application names.
- `Directives`: operator-supplied, verbatim — by design carries the
  operator's intent without trollbridge-side annotation.

### Soft concern A — `Identity` is operator-supplied

`Input.Identity` is the resolved identity token (mTLS CN, bearer
token, IP-mapping label). The value space comes from the operator's
config — they choose what names to use. If an operator labels an
identity as `claude-code-on-laptop-1` or `agentic-pipeline-prod`, the
LLM provider sees that label and can infer the host application's
role.

The principle's enforcement-statement says "no trollbridge-internal
identifiers"; identity values are NOT trollbridge-internal — they
are the operator's chosen labels. But they do carry application
context to the LLM if the operator chose descriptive names.

**Proposed fix.** Add an operator-facing note in
`docs/alignment-principles.md` §4 (or a new `docs/operator-best-
practices.md`) recommending that identity labels stay generic ("op",
"agent-1") rather than descriptive of the host application. Not a
code change; a documentation/review-pass change.

### Soft concern B — `Tool` is operator-supplied

`Input.Tool` is the originating tool name as resolved by the proxy
(MCP `tool=` parameter or equivalent). Like identity, the value
space is operator-supplied. A consumer that sets `tool=claude_code`
would expose the host application to the LLM provider.

**Proposed fix.** Same as concern A — operator-facing note. Could
additionally redact `tool` from the advisor input when its value
looks like an application name (regex pass against a small blocklist:
`claude*`, `gpt*`, `cursor*`, `codex*`, etc.). Marginal benefit;
risk of false positives.

## Principle 5 — LLM does not see prior LLM verdicts

**Verdict: clean.**

- `Input` has no prior-verdict field. `Service.Classify` takes no
  history parameter.
- `internal/policy/history.go` was scoped to human/static decisions
  in #141 (closed earlier this sweep) — LLM verdicts are no longer
  recorded.
- `DigestRing` is write-only from `Service.Classify`'s perspective;
  no code path reads back into a new consult.
- `TestInput_NoPriorVerdictChannel` (added in prior work) pins the
  Input field set so a re-introduced channel fails the build.

## Composition

The principles' compositional intent (limit what the LLM decides,
sees, and reasons about) is preserved end-to-end in trollbridge's
own code paths. The two soft concerns under principle 4 are
operator-config surfaces; they shift the responsibility to the
operator's naming choices, not trollbridge's data plumbing. The
principles document already notes "the operator chooses LLM
providers for capability, not for trustworthiness with sensitive
context" — operator-facing guidance on identity/tool naming would
extend that framing.

## Recommendations summary

| ID | Surface | Change | Filing |
|----|---------|--------|--------|
| A | `Input.Identity` / operator naming convention | Add operator-best-practices guidance | Non-blocking; doc commit |
| B | `Input.Tool` / operator naming convention | Same doc; optionally a redactor lane | Non-blocking; doc commit |

No code change is required to close #140 — the audit is the deliverable.
The two soft-concern follow-ups are scoped as separate work.
