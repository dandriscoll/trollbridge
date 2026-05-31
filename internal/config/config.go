// Package config loads and validates trollbridge.yaml. The schema is
// organised around per-surface bind values: each of `proxy`,
// `control`, `metrics` is a single `<host>:<port>` string. The host
// supports two aliases: `all` (= 0.0.0.0) and `lo` (= 127.0.0.1).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level shape of trollbridge.yaml.
type Config struct {
	// Per-surface binds. Each value combines host and port:
	//   proxy:   lo:8080         # 127.0.0.1
	//   control: 127.0.0.1:8081
	//   metrics: 0               # disabled
	// The host accepts the aliases "all" (= 0.0.0.0) and "lo"
	// (= 127.0.0.1); literal IPs and hostnames pass through.
	// Bracket IPv6 literals: "[fd00::1]:8081".
	Proxy   Bind `yaml:"proxy"`
	Control Bind `yaml:"control"`
	Metrics Bind `yaml:"metrics"`

	// Lists are the inline allow / deny patterns. trollbridge reads
	// them at startup; the console REPL writes them back via a
	// yaml-Node-level edit (see internal/configwrite).
	Lists Lists `yaml:"lists"`

	LLM LLM `yaml:"llm"`

	// Controller is the security posture for the operator-facing
	// control plane. mTLS over the existing CA is the only mode.
	Controller Controller `yaml:"controller"`

	Mode string `yaml:"mode"` // default-deny | default-allow | default-ask

	Interception  Interception  `yaml:"interception"`
	Redaction     Redaction     `yaml:"redaction"`
	Logging       Logging       `yaml:"logging"`
	Approvals     Approvals     `yaml:"approvals"`
	Forwarder     Forwarder     `yaml:"forwarder"`
	Shutdown      Shutdown      `yaml:"shutdown"`
	Identities    []Identity    `yaml:"identities"`
	Policy        Policy        `yaml:"policy"`
	Upstream      Upstream      `yaml:"upstream"`
	DecisionCache DecisionCache `yaml:"decisioncache"`
	TUI           TUI           `yaml:"tui"`
}

// TUI carries operator-UI options that affect the local TUI shell.
// They have no effect when trollbridge is run with --no-console or
// when stdin/stdout is not a TTY.
type TUI struct {
	Alerts TUIAlerts `yaml:"alerts"`
}

// TUIAlerts controls the operator-attention signals the TUI emits
// when new requests enter the pending state. The visual indicator
// (color + glyph on the pending count) is always on; only the
// audible chime is opt-out, because terminal bells can be annoying
// in shared environments (closes #72).
type TUIAlerts struct {
	// Chime, when true (the default), causes the TUI to emit a
	// single BEL character (`\x07`) on every tick where the pending
	// count increases. The TUI also supports a runtime toggle: press
	// `b` to flip the chime on or off without restarting.
	Chime *bool `yaml:"chime"`
}

// ChimeEnabled returns the effective chime flag: true unless the
// operator explicitly set `tui.alerts.chime: false` in config.
func (a TUIAlerts) ChimeEnabled() bool {
	if a.Chime == nil {
		return true
	}
	return *a.Chime
}

// Bind is a per-surface listen address: host + port. Port 0 means
// the surface is disabled (where the surface is optional).
type Bind struct {
	// Host is the resolved literal: "127.0.0.1", "0.0.0.0", "::",
	// a literal IP, or a hostname. Aliases (`all`, `lo`) have been
	// resolved by the time the field is populated.
	Host string
	// Port is 1..65535, or 0 to indicate disabled.
	Port int
	// Raw is the original YAML scalar, kept for error messages.
	Raw string
}

// UnmarshalYAML accepts a scalar (`lo:8080`, `all:8080`, `0`, `""`)
// and resolves it into a Bind. Validation that's surface-specific
// (e.g. proxy must not be disabled) runs in Config.validate.
func (b *Bind) UnmarshalYAML(node *yaml.Node) error {
	// Accept scalars only — `proxy: lo:8080`, not a mapping.
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("expected `<host>:<port>` scalar; got node kind %d", node.Kind)
	}
	parsed, err := parseBindScalar(node.Value)
	if err != nil {
		return err
	}
	*b = parsed
	return nil
}

// parseBindScalar converts a single yaml scalar into a Bind.
// Empty / "0" → disabled. Otherwise expects "<host>:<port>".
func parseBindScalar(raw string) (Bind, error) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "0" {
		return Bind{Raw: raw, Port: 0}, nil
	}
	host, port, err := splitHostPort(s)
	if err != nil {
		return Bind{}, fmt.Errorf("bad bind value %q: %s; expected `<host>:<port>` (e.g. `lo:8080`, `all:8080`, `127.0.0.1:8080`, `[fd00::1]:8081`)", raw, err)
	}
	host = resolveHostAlias(host)
	if port < 1 || port > 65535 {
		return Bind{}, fmt.Errorf("bad bind value %q: port %d outside 1..65535", raw, port)
	}
	return Bind{Host: host, Port: port, Raw: raw}, nil
}

// splitHostPort handles bracketed IPv6 (`[fd00::1]:8080`) and
// host:port. It does not accept a bare port or a bare host.
func splitHostPort(s string) (string, int, error) {
	if strings.HasPrefix(s, "[") {
		end := strings.LastIndex(s, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("missing closing ']' on IPv6 host")
		}
		host := s[1:end]
		rest := s[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", 0, fmt.Errorf("missing ':<port>' after IPv6 host")
		}
		port, err := strconv.Atoi(rest[1:])
		if err != nil {
			return "", 0, fmt.Errorf("port not an integer: %q", rest[1:])
		}
		return host, port, nil
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", 0, fmt.Errorf("missing port (use `host:port`)")
	}
	host := s[:idx]
	if host == "" {
		return "", 0, fmt.Errorf("missing host (use `lo:%s` or `all:%s`)", s[idx+1:], s[idx+1:])
	}
	port, err := strconv.Atoi(s[idx+1:])
	if err != nil {
		return "", 0, fmt.Errorf("port not an integer: %q", s[idx+1:])
	}
	return host, port, nil
}

// resolveHostAlias maps `all` → `0.0.0.0` and `lo` → `127.0.0.1`.
// Other values pass through.
func resolveHostAlias(h string) string {
	switch strings.ToLower(strings.TrimSpace(h)) {
	case "all":
		return "0.0.0.0"
	case "lo":
		return "127.0.0.1"
	}
	return h
}

// Disabled returns true when the surface is off (port 0 / empty).
func (b Bind) Disabled() bool { return b.Port == 0 }

// Addr returns "<host>:<port>", bracketing IPv6 literals. Returns
// "" when the bind is disabled.
func (b Bind) Addr() string {
	if b.Disabled() {
		return ""
	}
	host := b.Host
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", host, b.Port)
}

// ClientHost returns the address a client co-located with the daemon
// should dial. Wildcard binds collapse to loopback; everything else
// passes through (with IPv6 bracketed for URL use).
func (b Bind) ClientHost() string {
	switch b.Host {
	case "", "0.0.0.0":
		return "127.0.0.1"
	case "::", "[::]":
		return "[::1]"
	}
	if ip := net.ParseIP(b.Host); ip != nil && ip.To4() == nil {
		return "[" + b.Host + "]"
	}
	return b.Host
}

// ClientAddr returns "<client-host>:<port>" for a client on the same
// host as the daemon. Returns "" when the bind is disabled.
func (b Bind) ClientAddr() string {
	if b.Disabled() {
		return ""
	}
	return fmt.Sprintf("%s:%d", b.ClientHost(), b.Port)
}

// Lists holds the inline allow / deny patterns. Each entry follows
// the matcher syntax in internal/hostlist (host[:port][/path] with
// optional `<scheme>://` prefix; `*` wildcards).
type Lists struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`

	// DeclinedSuggestions records source-entry sets the operator
	// has declined to generalize. The section is automatically
	// managed by trollbridge: rows are appended when the operator
	// rejects every applicable axis for a given source set, and
	// the detector consults the section on every wake so the same
	// set is never re-offered. Closes part of #168.
	DeclinedSuggestions []DeclinedSuggestion `yaml:"declined_suggestions,omitempty"`
}

// DeclinedSuggestion is one row in lists.declined_suggestions. The
// canonical key (for de-duplication and detector filtering) is the
// sorted SourceEntries slice; axes_declined and declined_at are
// record-keeping fields, not part of the key.
type DeclinedSuggestion struct {
	SourceEntries []string `yaml:"source_entries"`
	AxesDeclined  []string `yaml:"axes_declined,omitempty"`
	DeclinedAt    string   `yaml:"declined_at,omitempty"` // RFC3339; string to keep YAML round-trips clean
}

// Controller carries the control-plane mTLS configuration. mTLS is
// the only supported mode in v3; the field is present for forward
// compatibility (e.g., adding `auth: oauth2` later).
type Controller struct {
	Auth         string `yaml:"auth"`
	ClientCAPath string `yaml:"client_ca_path"`
}

type Interception struct {
	Enabled          bool        `yaml:"enabled"`
	CA               CACfg       `yaml:"ca"`
	LeafKeyType      string      `yaml:"leaf_key_type"`
	PassthroughHosts []string    `yaml:"passthrough_hosts"`
	LeafCertTTLHours int         `yaml:"leaf_cert_ttl_hours"`
	OriginTrust      OriginTrust `yaml:"origin_trust"`
}

type OriginTrust struct {
	Mode string `yaml:"mode"`
	Path string `yaml:"path"`
}

type CACfg struct {
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
}

type LLM struct {
	Enabled         bool   `yaml:"enabled"`
	Provider        string `yaml:"provider"`
	Model           string `yaml:"model"`
	Endpoint        string `yaml:"endpoint"`
	APIKeyPath      string `yaml:"api_key_path"`
	TimeoutSeconds  int    `yaml:"timeout_seconds"`
	CacheTTLSeconds int    `yaml:"cache_ttl_seconds"`
	SendBody        bool   `yaml:"send_body"`
	OnUnavailable   string `yaml:"on_unavailable"`
	ConfidenceFloor string `yaml:"confidence_floor"`

	// Mode selects the advisor's operating shape (closes #54):
	//   review   — classify against the operator's allow/deny lists
	//              (the lists ride in advisor.Input as context).
	//   research — same as review, plus the LLM may invoke a web
	//              search tool for URL context. Anthropic-only;
	//              AOAI deployments warn at startup and run as
	//              review.
	// Empty defaults to "review".
	Mode string `yaml:"mode"`

	// Directives is an inline multi-line system prompt the advisor
	// composes onto every classification request, after trollbridge's
	// mode-baseline framing (closes #54).
	Directives string `yaml:"directives"`
}

type Redaction struct {
	DefaultModifiers []string        `yaml:"default_modifiers"`
	BodyRedactors    []BodyRedactor  `yaml:"body_redactors"`
	QueryRedactors   []QueryRedactor `yaml:"query_redactors"`
}

type BodyRedactor struct {
	JSONPath string `yaml:"jsonpath"`
	Regex    string `yaml:"regex"`
}

type QueryRedactor struct {
	Regex string `yaml:"regex"`
}

type Logging struct {
	AuditPath       string `yaml:"audit_path"`
	AuditBufferSize int    `yaml:"audit_buffer_size"`
	AuditOverflow   string `yaml:"audit_overflow"`
	// AuditLevel controls which audit entries land on disk:
	//   "all"       — every entry (default; current behavior).
	//   "decisions" — only entries from a human (approval queue,
	//                 including timeout) or the LLM advisor.
	//   "none"      — drop every entry.
	// See #113.
	AuditLevel      string `yaml:"audit_level"`
	OperationalPath string `yaml:"operational_path"`
}

type Approvals struct {
	TimeoutSeconds int    `yaml:"timeout_seconds"`
	OnTimeout      string `yaml:"on_timeout"`
	MaxPending     int    `yaml:"max_pending"`
	// SignalAfterSeconds, when > 0, controls how long the proxy
	// blocks a held request before sending a 471 pending response
	// (with the hold id) to the consumer and closing. The hold
	// itself remains in the queue for operator resolution; the
	// resolution is logged at INFO but not delivered to the now-
	// disconnected consumer. 0 (the default) preserves the
	// pre-#43 behavior of blocking until timeout_seconds.
	SignalAfterSeconds int `yaml:"signal_after_seconds"`

	// Suggestion governs the quiet-moment generalization-suggestion
	// flow (closes #168). When enabled and the proxy is idle (no
	// inbound traffic and no pending holds), trollbridge runs a
	// deterministic detector across the current allow/deny lists;
	// when an opportunity exists, the LLM ranks/narrates the
	// candidate and one row appears in the pending area.
	Suggestion ApprovalsSuggestion `yaml:"suggestion"`
}

// ApprovalsSuggestion carries the operator-tunable knobs for the
// quiet-moment suggestion detector.
type ApprovalsSuggestion struct {
	// Enabled gates the whole flow. nil → default true when
	// llm.enabled is true; false explicitly disables.
	Enabled *bool `yaml:"enabled"`
	// QuietIdleSeconds is the minimum duration the proxy must be
	// idle (queue empty AND no inbound request received) before
	// the detector wakes. Default 30.
	QuietIdleSeconds int `yaml:"quiet_idle_seconds"`
	// MaxCandidates caps the number of detector candidates passed
	// to the LLM in one ask. Default 8.
	MaxCandidates int `yaml:"max_candidates"`
	// PathConcentrationThreshold (#190) lets the scorer prefer a
	// narrower allow when the broader candidate's source entries
	// cluster heavily under a single 1-segment path prefix. Range
	// (0, 1]. Default 0.8: at least 80% of the broader's entries
	// must share a prefix with the narrower candidate to swap. A
	// zero value uses the default — operators set this to a non-
	// zero fraction to tune, not to disable.
	PathConcentrationThreshold float64 `yaml:"path_concentration_threshold"`
}

// EnabledFor reports whether the suggestion flow should run given
// the LLM config. Nil Enabled defaults to true when llm.enabled is
// true; an explicit false in YAML disables regardless.
func (s ApprovalsSuggestion) EnabledFor(llm LLM) bool {
	if s.Enabled != nil {
		return *s.Enabled
	}
	return llm.Enabled
}

type Forwarder struct {
	MaxIdleConns                    int `yaml:"max_idle_connections"`
	MaxIdleConnsPerHost             int `yaml:"max_idle_connections_per_host"`
	ConnectionAcquireTimeoutSeconds int `yaml:"connection_acquire_timeout_seconds"`
}

type Shutdown struct {
	GraceSeconds int `yaml:"grace_seconds"`
}

type Identity struct {
	ID    string        `yaml:"id"`
	Match IdentityMatch `yaml:"match"`
}

type IdentityMatch struct {
	MTLSCN            string `yaml:"mtls_cn"`
	BearerTokenSHA256 string `yaml:"bearer_token_sha256"`
	SourceIP          string `yaml:"source_ip"`
}

type Policy struct {
	Include []string `yaml:"include"`
}

type Upstream struct {
	Proxy   string   `yaml:"proxy"`
	NoProxy []string `yaml:"no_proxy"`
}

type DecisionCache struct {
	TTLSeconds int `yaml:"ttl_seconds"`
}

// Load reads config from path, applies defaults, validates, and
// returns the resulting Config. Decoding is strict: a YAML key with
// no matching struct field — a typo (`mod:` for `mode:`), or an
// unsupported block — fails the load loudly rather than being
// silently discarded (#123).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// Issue #27: when the file is missing, name the well-known
		// next step (`trollbridge init`) inline. The advertised CLI
		// surface gives an unfriendly bare ENOENT otherwise.
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config file not found at %s. Run `trollbridge init` to create one (or `trollbridge quickstart` to write a minimal default and start the proxy in one step)", path)
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	// KnownFields(true) makes the decoder reject unknown keys. Decode
	// returns io.EOF on an empty or comments-only file; that is not an
	// error here — the zero Config flows through applyDefaults and
	// validate exactly as it did under the prior yaml.Unmarshal path.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	// Reject a `---`-separated second document with content. Decode
	// reads one document per call, so a trailing document would
	// otherwise be silently ignored (#126). A bare trailing
	// separator yields a null document — harmless, tolerated.
	for {
		var extra any
		err := dec.Decode(&extra)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
		if extra != nil {
			return nil, fmt.Errorf("parse config %s: multiple YAML documents found; trollbridge reads a single document per file", path)
		}
	}
	cfg.applyDefaults()
	if err := cfg.validate(path); err != nil {
		return nil, err
	}
	// Non-fatal advisory when the (validated) llm.endpoint targets a
	// private address — see checkLLMEndpoint. Emitted here because
	// validate() has no warning channel.
	if cfg.LLM.Enabled && cfg.LLM.Endpoint != "" {
		if w, _ := checkLLMEndpoint(cfg.LLM.Endpoint); w != "" {
			slog.Warn("config: "+w, "field", "llm.endpoint", "config", path)
		}
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	// Distinguish "field absent" (Raw == "") from "explicit disable"
	// (Raw == "0"). Absent → apply default; explicit-0 → keep
	// disabled and let validate() reject if the surface is required.
	if c.Proxy.Raw == "" && c.Proxy.Port == 0 {
		c.Proxy = Bind{Host: "127.0.0.1", Port: 8080, Raw: "lo:8080"}
	}
	// Control / Metrics default to disabled. `trollbridge init`
	// writes an explicit `control: lo:8081` so a fresh install gets
	// a working controller without surprise.
	if c.Controller.Auth == "" {
		c.Controller.Auth = "mtls"
	}
	if c.Mode == "" {
		c.Mode = "default-deny"
	}
	if c.Interception.LeafKeyType == "" {
		c.Interception.LeafKeyType = "rsa-4096"
	}
	if c.Interception.LeafCertTTLHours == 0 {
		c.Interception.LeafCertTTLHours = 24
	}
	if c.Logging.AuditBufferSize == 0 {
		c.Logging.AuditBufferSize = 1024
	}
	if c.Logging.AuditOverflow == "" {
		c.Logging.AuditOverflow = "deny"
	}
	if c.Logging.AuditLevel == "" {
		c.Logging.AuditLevel = "all"
	}
	if c.Logging.OperationalPath == "" {
		c.Logging.OperationalPath = "stderr"
	}
	if c.Approvals.TimeoutSeconds == 0 {
		c.Approvals.TimeoutSeconds = 300
	}
	if c.Approvals.OnTimeout == "" {
		c.Approvals.OnTimeout = "deny"
	}
	if c.Approvals.MaxPending == 0 {
		c.Approvals.MaxPending = 100
	}
	if c.Approvals.Suggestion.QuietIdleSeconds == 0 {
		c.Approvals.Suggestion.QuietIdleSeconds = 30
	}
	if c.Approvals.Suggestion.MaxCandidates == 0 {
		c.Approvals.Suggestion.MaxCandidates = 8
	}
	if c.Approvals.Suggestion.PathConcentrationThreshold <= 0 ||
		c.Approvals.Suggestion.PathConcentrationThreshold > 1 {
		c.Approvals.Suggestion.PathConcentrationThreshold = 0.8
	}
	if c.Forwarder.MaxIdleConns == 0 {
		c.Forwarder.MaxIdleConns = 256
	}
	if c.Forwarder.MaxIdleConnsPerHost == 0 {
		c.Forwarder.MaxIdleConnsPerHost = 32
	}
	if c.Forwarder.ConnectionAcquireTimeoutSeconds == 0 {
		c.Forwarder.ConnectionAcquireTimeoutSeconds = 5
	}
	if c.Shutdown.GraceSeconds == 0 {
		c.Shutdown.GraceSeconds = 30
	}
	if c.DecisionCache.TTLSeconds == 0 {
		c.DecisionCache.TTLSeconds = 60
	}
	if c.LLM.TimeoutSeconds == 0 {
		c.LLM.TimeoutSeconds = 8
	}
	if c.LLM.OnUnavailable == "" {
		c.LLM.OnUnavailable = "ask_user"
	}
	if c.LLM.Mode == "" {
		c.LLM.Mode = "review"
	}
}

func (c *Config) validate(path string) error {
	switch c.Mode {
	case "default-deny", "default-allow", "default-ask":
	default:
		return fmt.Errorf("config error in %s: `mode` must be one of `default-deny`, `default-allow`, `default-ask`. Got: %q.", path, c.Mode)
	}
	switch c.Controller.Auth {
	case "mtls":
	default:
		return fmt.Errorf("config error in %s: `controller.auth` must be `mtls`. Got: %q.", path, c.Controller.Auth)
	}
	switch c.Logging.AuditOverflow {
	case "deny", "drop", "block":
	default:
		return fmt.Errorf("config error in %s: `logging.audit_overflow` must be one of `deny`, `drop`, `block`. Got: %q.", path, c.Logging.AuditOverflow)
	}
	switch c.Logging.AuditLevel {
	case "none", "decisions", "all":
	default:
		return fmt.Errorf("config error in %s: `logging.audit_level` must be one of `none`, `decisions`, `all`. Got: %q.", path, c.Logging.AuditLevel)
	}
	switch c.Interception.LeafKeyType {
	case "rsa-4096", "ecdsa-p256":
	default:
		return fmt.Errorf("config error in %s: `interception.leaf_key_type` must be `rsa-4096` or `ecdsa-p256`. Got: %q.", path, c.Interception.LeafKeyType)
	}
	switch c.LLM.Mode {
	case "review", "research":
	default:
		return fmt.Errorf("config error in %s: `llm.mode` must be `review` or `research`. Got: %q.", path, c.LLM.Mode)
	}
	if c.Proxy.Disabled() {
		return fmt.Errorf("config error in %s: `proxy` is required (e.g. `proxy: lo:8080`)", path)
	}
	// Port range checks already happen in parseBindScalar; surface
	// the same shape here for any field that bypassed the parser.
	if c.Proxy.Port < 1 || c.Proxy.Port > 65535 {
		return fmt.Errorf("config error in %s: `proxy` port %d outside 1..65535", path, c.Proxy.Port)
	}
	if !c.Control.Disabled() && (c.Control.Port < 1 || c.Control.Port > 65535) {
		return fmt.Errorf("config error in %s: `control` port %d outside 1..65535", path, c.Control.Port)
	}
	if !c.Metrics.Disabled() && (c.Metrics.Port < 1 || c.Metrics.Port > 65535) {
		return fmt.Errorf("config error in %s: `metrics` port %d outside 1..65535", path, c.Metrics.Port)
	}
	// Same-host-same-port collisions are illegal. Different hosts
	// at the same port are legal; the kernel will reject if the
	// hosts overlap (e.g. all:8080 + lo:8080 collide on bind).
	if !c.Control.Disabled() && c.Proxy.Host == c.Control.Host && c.Proxy.Port == c.Control.Port {
		return fmt.Errorf("config error in %s: `proxy` and `control` collide on %s", path, c.Proxy.Addr())
	}
	if !c.Metrics.Disabled() {
		if c.Proxy.Host == c.Metrics.Host && c.Proxy.Port == c.Metrics.Port {
			return fmt.Errorf("config error in %s: `proxy` and `metrics` collide on %s", path, c.Proxy.Addr())
		}
		if !c.Control.Disabled() && c.Control.Host == c.Metrics.Host && c.Control.Port == c.Metrics.Port {
			return fmt.Errorf("config error in %s: `control` and `metrics` collide on %s", path, c.Control.Addr())
		}
	}
	for i, id := range c.Identities {
		if id.ID == "" {
			return fmt.Errorf("config error in %s: identity at index %d missing `id`.", path, i)
		}
	}
	// Reject the dangerous llm.endpoint shapes at load. The non-fatal
	// private-address advisory is surfaced separately by Load via slog
	// (validate has no warning channel).
	if c.LLM.Enabled && c.LLM.Endpoint != "" {
		if _, err := checkLLMEndpoint(c.LLM.Endpoint); err != nil {
			return fmt.Errorf("config error in %s: %w", path, err)
		}
	}
	return nil
}

// checkLLMEndpoint inspects llm.endpoint for the cleartext / private-
// redirect shapes. An agent with filesystem write access (the documented
// design trade-off) could otherwise repoint the advisor at an internal
// or unintended host and leak the request metadata the proxy sends to
// the LLM.
//
// It is pure: it does NO DNS resolution or other I/O, so it is fast,
// deterministic, and safe to call at config-load. Host classification is
// therefore limited to literal IPs (net.ParseIP); a hostname that
// resolves to a private address is not caught here — an accepted,
// documented limitation, since resolving attacker-influenced DNS at load
// is itself undesirable.
//
// Returns a fatal err for the dangerous shapes (unparseable; non-private
// host over cleartext http) and a non-fatal warn string for the
// legitimate-but-noteworthy local-advisor shape (a loopback/RFC-1918
// target), so a privacy-conscious operator running a local LLM advisor
// keeps working while still being told that a writable config pointing
// the advisor at a private target can redirect request metadata.
func checkLLMEndpoint(endpoint string) (warn string, err error) {
	u, perr := url.Parse(endpoint)
	if perr != nil {
		return "", fmt.Errorf("`llm.endpoint` is not a valid URL (%q): %v", endpoint, perr)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("`llm.endpoint` has no host (%q); expected e.g. https://api.example.com/...", endpoint)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("`llm.endpoint` must use http or https (got scheme %q in %q)", u.Scheme, endpoint)
	}
	ip := net.ParseIP(host)
	private := ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())
	if u.Scheme == "http" {
		if !private {
			return "", fmt.Errorf("`llm.endpoint` must use https for a non-private host (got %q); cleartext http would send advisor request metadata in the clear", endpoint)
		}
		return fmt.Sprintf("`llm.endpoint` uses http to a private address (%q); ok for a local advisor, but if this config is agent-writable it can redirect advisor request metadata to an unintended host", host), nil
	}
	// https
	if private {
		return fmt.Sprintf("`llm.endpoint` targets a private address (%q); if this config is agent-writable it can redirect advisor request metadata to an unintended host", host), nil
	}
	return "", nil
}

// ResolveIncludePaths returns rule-file paths from c.Policy.Include
// resolved relative to the config file's directory.
func (c *Config) ResolveIncludePaths(configPath string) []string {
	return resolveRelative(configPath, c.Policy.Include)
}

func resolveRelative(configPath string, items []string) []string {
	dir := filepath.Dir(configPath)
	out := make([]string, 0, len(items))
	for _, p := range items {
		if filepath.IsAbs(p) {
			out = append(out, p)
		} else {
			out = append(out, filepath.Join(dir, p))
		}
	}
	return out
}
