// Package config loads and validates drawbridge.yaml. v2 schema is
// organised around the four operator decisions: which adapter the
// daemon is open on, what is allowed/denied, what LLM is used as the
// advisor, and what directives the advisor follows.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the current drawbridge.yaml schema version.
const SchemaVersion = 2

// Config is the top-level shape of drawbridge.yaml (v2).
type Config struct {
	DrawbridgeVersion int `yaml:"drawbridge_version"`

	// The four decisions: foregrounded.

	// Adapter is one of: `lo` (loopback), `0.0.0.0` (all interfaces),
	// or a literal IP address / hostname. Used to bind the proxy,
	// control plane, and (optionally) the metrics endpoint.
	Adapter string `yaml:"adapter"`

	// Ports for each surface. 0 disables.
	Ports Ports `yaml:"ports"`

	// Lists are the inline allow / deny patterns. drawbridge reads
	// them at startup; the console REPL writes them back via a
	// yaml-Node-level edit (see internal/configwrite).
	Lists Lists `yaml:"lists"`

	LLM LLM `yaml:"llm"`

	// Controller is the security posture for the operator-facing
	// control plane. mTLS over the existing CA is the only mode.
	Controller Controller `yaml:"controller"`

	// Secondary configuration; defaults usually fine.

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
}

// Ports is the flat per-surface port map. All three surfaces bind to
// `<adapter>:<port>`. Port 0 disables the surface.
type Ports struct {
	Proxy   int `yaml:"proxy"`
	Control int `yaml:"control"`
	Metrics int `yaml:"metrics"`
}

// Lists holds the inline allow / deny patterns. Each entry follows
// the matcher syntax in internal/hostlist (host[:port][/path] with
// optional `<scheme>://` prefix; `*` wildcards).
type Lists struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// Controller carries the control-plane mTLS configuration. mTLS is
// the only supported mode in v2; the field is present for forward
// compatibility (e.g., adding `auth: oauth2` later).
type Controller struct {
	// Auth must be "mtls" (default and only valid value in v2).
	Auth string `yaml:"auth"`

	// ClientCAPath optionally overrides the CA used to verify
	// operator client certs. When empty, drawbridge uses the
	// interception CA (`interception.ca.cert_path`). Listing this
	// separately is the escape hatch for an operator who wants the
	// controller to trust a different CA than the proxy.
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

	// Directives is an inline multi-line system prompt the advisor
	// composes onto every classification request.
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
	OperationalPath string `yaml:"operational_path"`
}

// Approvals controls the held-request queue — separate from the
// controller's auth posture, which lives under `controller`.
type Approvals struct {
	TimeoutSeconds int    `yaml:"timeout_seconds"`
	OnTimeout      string `yaml:"on_timeout"`
	MaxPending     int    `yaml:"max_pending"`
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
// returns the resulting Config. Rejects v1 configs with a migration
// message that names what changed.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var probe struct {
		Version int `yaml:"drawbridge_version"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if probe.Version == 1 {
		return nil, fmt.Errorf(`config error in %s: drawbridge_version 1 is no longer supported.
v2 reorganises the schema around four decisions:
  - adapter:  one network interface for proxy/control/metrics (replaces listen.address + approvals.control_listen + logging.metrics_listen)
  - ports:    flat block (proxy / control / metrics) on the chosen adapter
  - lists:    inline allow/deny (replaces policy.allow_files / deny_files; .txt files no longer used)
  - llm:      provider/model/key + an inline llm.directives multi-line string
And replaces bearer-auth on the control plane with mTLS:
  - controller.auth: mtls (default)
  - issue an operator client cert with: drawbridge ca client-cert <name>
Add 'drawbridge_version: 2' to the top of your file and migrate the
fields above. See config.example.yaml for the canonical v2 shape.`, path)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(path); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.DrawbridgeVersion == 0 {
		c.DrawbridgeVersion = SchemaVersion
	}
	if c.Adapter == "" {
		c.Adapter = "lo"
	}
	if c.Ports.Proxy == 0 {
		c.Ports.Proxy = 8080
	}
	// Ports.Control = 0 means the operator-facing control plane is
	// disabled (CLI clients have nothing to connect to). The example
	// yaml + `drawbridge init` write 8081 explicitly so the default
	// install gets a working controller without surprise.
	// Ports.Metrics = 0 means Prometheus endpoint disabled.
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
}

func (c *Config) validate(path string) error {
	if c.DrawbridgeVersion != SchemaVersion {
		return fmt.Errorf("config error in %s: drawbridge_version must be %d; got %d", path, SchemaVersion, c.DrawbridgeVersion)
	}
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
	switch c.Interception.LeafKeyType {
	case "rsa-4096", "ecdsa-p256":
	default:
		return fmt.Errorf("config error in %s: `interception.leaf_key_type` must be `rsa-4096` or `ecdsa-p256`. Got: %q.", path, c.Interception.LeafKeyType)
	}
	if c.Ports.Proxy < 1 || c.Ports.Proxy > 65535 {
		return fmt.Errorf("config error in %s: `ports.proxy` must be 1..65535. Got: %d.", path, c.Ports.Proxy)
	}
	if c.Ports.Control != 0 && (c.Ports.Control < 1 || c.Ports.Control > 65535) {
		return fmt.Errorf("config error in %s: `ports.control` must be 0 (disabled) or 1..65535. Got: %d.", path, c.Ports.Control)
	}
	if c.Ports.Metrics != 0 && (c.Ports.Metrics < 1 || c.Ports.Metrics > 65535) {
		return fmt.Errorf("config error in %s: `ports.metrics` must be 0 (disabled) or 1..65535. Got: %d.", path, c.Ports.Metrics)
	}
	if c.Ports.Control != 0 && c.Ports.Proxy == c.Ports.Control {
		return fmt.Errorf("config error in %s: `ports.proxy` and `ports.control` must differ; both are %d.", path, c.Ports.Proxy)
	}
	for i, id := range c.Identities {
		if id.ID == "" {
			return fmt.Errorf("config error in %s: identity at index %d missing `id`.", path, i)
		}
	}
	return nil
}

// BindHost returns the literal address the daemon should `net.Listen`
// on for the configured adapter.
//
//	"lo"      -> "127.0.0.1"
//	"0.0.0.0" -> "0.0.0.0"
//	"::"      -> "::"
//	literal IP / hostname -> pass-through
func (c *Config) BindHost() string {
	switch c.Adapter {
	case "lo", "":
		return "127.0.0.1"
	}
	return c.Adapter
}

// BindAddr returns "<bind-host>:<port>" for the supplied port; for
// IPv6 literals the host is bracketed.
func (c *Config) BindAddr(port int) string {
	host := c.BindHost()
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", host, port)
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
