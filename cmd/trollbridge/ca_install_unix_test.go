//go:build !windows

package main

import (
	"testing"
)

// TestFindInstallCert_FallsThroughToCanonical verifies that when the
// configured path is absent, the search falls through to the Debian
// trust-store drop-in candidate. Unix-only because that fallback
// candidate is /usr/local/share/ca-certificates/... — a Linux/Debian
// convention; the Windows-side candidate list is different.
func TestFindInstallCert_FallsThroughToCanonical(t *testing.T) {
	stat := fakeStat{"/usr/local/share/ca-certificates/trollbridge-ca.crt": true}.stat
	got, err := findInstallCert("", "/conf/missing.pem", stat)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != "/usr/local/share/ca-certificates/trollbridge-ca.crt" {
		t.Errorf("got %q, want /usr/local/share/ca-certificates/trollbridge-ca.crt", got)
	}
}

// TestFindInstallCert_PrefersEtcOverShare pins the candidate ordering
// in unix: when both /etc/trollbridge and the Debian drop-in exist,
// /etc wins. Unix-only because both paths are unix-specific.
func TestFindInstallCert_PrefersEtcOverShare(t *testing.T) {
	stat := fakeStat{
		"/etc/trollbridge/trollbridge-ca.crt":                 true,
		"/usr/local/share/ca-certificates/trollbridge-ca.crt": true,
	}.stat
	got, err := findInstallCert("", "", stat)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != "/etc/trollbridge/trollbridge-ca.crt" {
		t.Errorf("got %q, want /etc/trollbridge/trollbridge-ca.crt", got)
	}
}
