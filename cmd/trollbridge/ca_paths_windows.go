//go:build windows

package main

// Daemon-mode defaults on Windows route to %ProgramData%\trollbridge.
// ProgramData is the system-wide writable convention for service
// state; the installer is expected to pre-create the directory with
// the appropriate ACLs for the trollbridge service account. The
// daemon never runs as Administrator, per the install-mode axis
// (closes #59).
const (
	DefaultCADir            = `C:\ProgramData\trollbridge`
	DefaultCACertPath       = `C:\ProgramData\trollbridge\trollbridge-ca.crt`
	DefaultCAKeyPath        = `C:\ProgramData\trollbridge\trollbridge-ca.key`
	DefaultDaemonAuditPath  = `C:\ProgramData\trollbridge\audit.jsonl`
	DefaultDaemonLLMKeyPath = `C:\ProgramData\trollbridge\llm.key`
)
