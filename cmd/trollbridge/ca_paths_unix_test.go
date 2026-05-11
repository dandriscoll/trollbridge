//go:build !windows

package main

import (
	"strings"
	"testing"
)

// TestDefaultPaths_AreEtcAbsoluteOnUnix pins #59's directive: Unix
// daemon-mode defaults stay under /etc/trollbridge or /var/log.
func TestDefaultPaths_AreEtcAbsoluteOnUnix(t *testing.T) {
	cases := map[string]string{
		"DefaultCADir":            "/etc/trollbridge",
		"DefaultCACertPath":       "/etc/trollbridge/trollbridge-ca.crt",
		"DefaultCAKeyPath":        "/etc/trollbridge/trollbridge-ca.key",
		"DefaultDaemonAuditPath":  "/var/log/trollbridge/audit.jsonl",
		"DefaultDaemonLLMKeyPath": "/etc/trollbridge/llm.key",
	}
	got := map[string]string{
		"DefaultCADir":            DefaultCADir,
		"DefaultCACertPath":       DefaultCACertPath,
		"DefaultCAKeyPath":        DefaultCAKeyPath,
		"DefaultDaemonAuditPath":  DefaultDaemonAuditPath,
		"DefaultDaemonLLMKeyPath": DefaultDaemonLLMKeyPath,
	}
	for name, want := range cases {
		if got[name] != want {
			t.Errorf("%s = %q, want %q", name, got[name], want)
		}
		if !strings.HasPrefix(got[name], "/") {
			t.Errorf("%s = %q is not absolute", name, got[name])
		}
	}
}
