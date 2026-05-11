//go:build !windows

package main

// DefaultCACertPath and DefaultCAKeyPath are the canonical daemon-mode
// locations for the trollbridge CA. They are absolute paths so the
// same value is valid on every machine: an operator who scp's a
// config from one host to another finds the cert at the same place.
// Cwd-relative paths (the prior default) are not cross-machine valid
// and were removed in v0.4.7 (issue #14). The Windows variant lives
// in ca_paths_windows.go and routes to %ProgramData% (closes #59).
const (
	DefaultCADir            = "/etc/trollbridge"
	DefaultCACertPath       = "/etc/trollbridge/trollbridge-ca.crt"
	DefaultCAKeyPath        = "/etc/trollbridge/trollbridge-ca.key"
	DefaultDaemonAuditPath  = "/var/log/trollbridge/audit.jsonl"
	DefaultDaemonLLMKeyPath = "/etc/trollbridge/llm.key"
)
