//go:build !windows

package main

// extraInstallCertCandidates lists the unix-only additional locations
// `ca install` searches for the trollbridge CA. The Debian trust-store
// drop-in is the canonical second location on Debian/Ubuntu; macOS
// admins typically place the cert at DefaultCACertPath instead.
func extraInstallCertCandidates() []string {
	return []string{"/usr/local/share/ca-certificates/trollbridge-ca.crt"}
}
