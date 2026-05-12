//go:build windows

package main

// extraInstallCertCandidates is empty on Windows. The Windows trust
// store is accessed through certutil/CryptoAPI rather than a
// filesystem drop-in directory; DefaultCACertPath under %ProgramData%
// is the only canonical search location.
func extraInstallCertCandidates() []string {
	return nil
}
