# Operating trollbridge

How to drive trollbridge interactively (the operator UI) and how to
run it as a background daemon. For installation, see
[`SETUP-AGENT.md`](../SETUP-AGENT.md) (agent-driven) or
[`PROXY-SETUP-AGENT.md`](../PROXY-SETUP-AGENT.md) (manual).

## The operator UI

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

### Keys

- `Tab` — switch focus between the approvals pane and the console
  pane.
- approvals pane: `a` approve · `d` deny · `↑↓` (or `j`/`k`) select ·
  `r` refresh now · `o` open · `c` close (while open) · `q` (or `Esc`)
  quit.
- console pane: type a command, `Enter` to run, `Backspace` to edit,
  `Ctrl-U` to clear the line, `Esc` to return to the approvals pane.
- anywhere: `Ctrl-C` quit.

### Open mode

Press `o` to open a time-boxed window that **allows all traffic**
without modifying the allow/deny lists — useful for letting an agent
run unattended for a short, deliberate burst. The first press opens the
proxy for **1 minute**; each further `o` extends it (`+1`, `+3`, `+5`,
`+20`, `+30` minutes, capped at `+30`). While open, the approvals-pane
border turns **amber** and the bottom border shows `[c] close (Ns)` with
the seconds remaining; press `c` to close immediately. The window
reverts to normal policy automatically when it lapses. Every request
allowed during the window is audited with `decision_source: open_mode`,
and the operational log records `open_mode_extended` / `open_mode_closed`
events, so the bypass is fully reviewable after the fact. Open mode is
also drivable from `trollbridge attach` over the control plane.

The approvals list refreshes automatically as the queue changes;
one-shot `trollbridge approve <id>` / `trollbridge deny <id>` remain
available for scripted use.

### Sticky approve / deny

Manual approve / deny decisions are **sticky**: pressing `a` writes
the request's URL pattern to `lists.allow` in `trollbridge.yaml`
(and pressing `d` writes to `lists.deny`), then re-loads the lists
in-process so the next request to the same URL matches the rule and
skips the queue (closes #49). The pattern is the request's full URL
today (`https://api.example.com:443/path` for HTTP, `host:port` for
CONNECT); LLM-driven generalization is planned. To approve once
without persisting, edit the YAML by hand or use the typed REPL
`allow <pattern>` for a more general match.

### Console REPL

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
under any circumstance. See
[`alignment-principles.md`](alignment-principles.md) for the four
principles governing the LLM advisor's role.

### Terminal requirements

The TUI assumes a UTF-8 terminal; on `LANG=C` or environments without
box-drawing rune support, run with `--no-console` (see *Daemon mode*
below).

### Driving the UI from another terminal

To drive the same UI from another terminal — over the daemon's mTLS
control plane — run:

```sh
trollbridge attach -c ~/.trollbridge/trollbridge.yaml
```

In `attach`, the approvals pane is fully functional; list editing,
test, and doctor commands stay on the proxy host (the console pane
prints a one-line "not available in attach mode" hint).

## Daemon mode

Pass `--no-console` to `trollbridge run` to suppress the operator UI.
The proxy listens, accepts requests, holds approvals, and writes the
operational log as in the interactive case — only the TUI is omitted.
Approvals can be driven from another host via `trollbridge attach`,
or auto-resolved by `approvals.timeout_seconds` (default-deny on
timeout) and `approvals.signal_after_seconds` (471 hold-signal to the
consumer at the configured cutoff). On startup the proxy emits one
INFO line:

```
event=startup install_mode=daemon ui=none default_decision=… approvals=in-process on_timeout=… [attach_endpoint=…]
```

naming the install mode for log-tailing operators.

## Validating configuration in CI

`trollbridge validate -c <path>` parses the config + included rules
+ inline lists and reports the result. Use this as a config-lint
step in your own CI.

- Without `--json`: prints a human-readable summary on stdout.
- With `--json`: prints a single JSON object on stdout with the same
  fields. Operators wiring this from CI bind to the object and the
  exit code; nothing prints to stderr when `--json` is set.

Exit-code contract (stable):

| code | meaning                                                                                                                                |
|------|----------------------------------------------------------------------------------------------------------------------------------------|
| 0    | configuration and rule set parse cleanly                                                                                               |
| 1    | any validation failure — file missing, YAML parse error, unknown key (strict decoding rejects typos, #123), list parse error, &c.       |

```sh
trollbridge validate --json -c /etc/trollbridge/trollbridge.yaml \
  | jq -e '.ok' >/dev/null \
  || { echo "config invalid"; exit 1; }
```

Run `trollbridge doctor -c <path>` after editing the YAML for a
richer check — it loads the config, parses the rules and lists, and
(when LLM is enabled) issues a real classification call so
misconfigured endpoints / keys / providers fail loud before
`trollbridge run`.
