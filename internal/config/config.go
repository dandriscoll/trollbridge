// Package config loads and validates drawbridge.yaml plus referenced
// rule files. See DESIGN.md §13.4.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the top-level shape of drawbridge.yaml.
type Config struct {
	DrawbridgeVersion int `yaml:"drawbridge_version"`

	Listen Listen `yaml:"listen"`
	Mode   string `yaml:"mode"` // default-deny | default-allow | default-ask

	Interception  Interception  `yaml:"interception"`
	LLM           LLM           `yaml:"llm"`
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

type Listen struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

type Interception struct {
	Enabled          bool        `yaml:"enabled"`
	CA               CACfg       `yaml:"ca"`
	LeafKeyType      string      `yaml:"leaf_key_type"` // rsa-4096 | ecdsa-p256
	PassthroughHosts []string    `yaml:"passthrough_hosts"`
	LeafCertTTLHours int         `yaml:"leaf_cert_ttl_hours"`
	OriginTrust      OriginTrust `yaml:"origin_trust"`
}

// OriginTrust controls how drawbridge verifies origin TLS certs.
//   mode: "system" (default), "file", or "mixed"
//   path: PEM file with extra trust roots (mode=file or mixed)
type OriginTrust struct {
	Mode string `yaml:"mode"`
	Path string `yaml:"path"`
}

type CACfg struct {
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
}

type LLM struct {
	Enabled          bool   `yaml:"enabled"`
	Provider         string `yaml:"provider"`
	Model            string `yaml:"model"`
	Endpoint         string `yaml:"endpoint"`
	APIKeyPath       string `yaml:"api_key_path"`
	TimeoutSeconds   int    `yaml:"timeout_seconds"`
	CacheTTLSeconds  int    `yaml:"cache_ttl_seconds"`
	SendBody         bool   `yaml:"send_body"`
	OnUnavailable    string `yaml:"on_unavailable"`
	ConfidenceFloor  string `yaml:"confidence_floor"`
}

type Redaction struct {
	DefaultModifiers []string         `yaml:"default_modifiers"`
	BodyRedactors    []BodyRedactor   `yaml:"body_redactors"`
	QueryRedactors   []QueryRedactor  `yaml:"query_redactors"`
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
	AuditOverflow   string `yaml:"audit_overflow"` // deny | drop | block
	OperationalPath string `yaml:"operational_path"`
	MetricsListen   string `yaml:"metrics_listen"`
}

type Approvals struct {
	ControlListen     string `yaml:"control_listen"`
	TimeoutSeconds    int    `yaml:"timeout_seconds"`
	OnTimeout         string `yaml:"on_timeout"`
	MaxPending        int    `yaml:"max_pending"`
	ControlAuthMode   string `yaml:"control_auth_mode"`        // none | bearer
	ControlBearerSHA  string `yaml:"control_bearer_token_sha256"`
}

type Forwarder struct {
	MaxIdleConns                  int `yaml:"max_idle_connections"`
	MaxIdleConnsPerHost           int `yaml:"max_idle_connections_per_host"`
	ConnectionAcquireTimeoutSeconds int `yaml:"connection_acquire_timeout_seconds"`
}

type Shutdown struct {
	GraceSeconds int `yaml:"grace_seconds"`
}

type Identity struct {
	ID    string         `yaml:"id"`
	Match IdentityMatch  `yaml:"match"`
}

type IdentityMatch struct {
	MTLSCN             string `yaml:"mtls_cn"`
	BearerTokenSHA256  string `yaml:"bearer_token_sha256"`
	SourceIP           string `yaml:"source_ip"`
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
// returns the resulting Config.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
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
		c.DrawbridgeVersion = 1
	}
	if c.Listen.Address == "" {
		c.Listen.Address = "127.0.0.1"
	}
	if c.Listen.Port == 0 {
		c.Listen.Port = 8080
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
	switch c.Mode {
	case "default-deny", "default-allow", "default-ask":
	default:
		return fmt.Errorf("config error in %s: `mode` must be one of `default-deny`, `default-allow`, `default-ask`. Got: %q. Fix: correct the typo.", path, c.Mode)
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
	if c.Listen.Port < 1 || c.Listen.Port > 65535 {
		return fmt.Errorf("config error in %s: `listen.port` must be 1..65535. Got: %d.", path, c.Listen.Port)
	}
	for i, id := range c.Identities {
		if id.ID == "" {
			return fmt.Errorf("config error in %s: identity at index %d missing `id`.", path, i)
		}
	}
	return nil
}

// ResolveIncludePaths returns rule-file paths from c.Policy.Include
// resolved relative to the config file's directory.
func (c *Config) ResolveIncludePaths(configPath string) []string {
	dir := filepath.Dir(configPath)
	out := make([]string, 0, len(c.Policy.Include))
	for _, p := range c.Policy.Include {
		if filepath.IsAbs(p) {
			out = append(out, p)
		} else {
			out = append(out, filepath.Join(dir, p))
		}
	}
	return out
}
