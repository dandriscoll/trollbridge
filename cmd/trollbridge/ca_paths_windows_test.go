//go:build windows

package main

import (
	"strings"
	"testing"
)

// TestDefaultPaths_AreProgramDataAbsoluteOnWindows pins #59's
// directive: Windows daemon-mode defaults live under
// %ProgramData% as absolute paths.
func TestDefaultPaths_AreProgramDataAbsoluteOnWindows(t *testing.T) {
	for name, p := range map[string]string{
		"DefaultCADir":            DefaultCADir,
		"DefaultCACertPath":       DefaultCACertPath,
		"DefaultCAKeyPath":        DefaultCAKeyPath,
		"DefaultDaemonAuditPath":  DefaultDaemonAuditPath,
		"DefaultDaemonLLMKeyPath": DefaultDaemonLLMKeyPath,
	} {
		if !strings.HasPrefix(strings.ToLower(p), `c:\programdata\trollbridge`) {
			t.Errorf("%s = %q, want prefix C:\\ProgramData\\trollbridge", name, p)
		}
	}
}
