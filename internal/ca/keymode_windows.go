//go:build windows

package ca

// checkKeyMode is a no-op on Windows. POSIX permission bits are not
// the protection mechanism here — os.Stat reports 0o666 for any file
// and chmod is best-effort — and NTFS ACLs govern access instead.
// The unix variant in keymode_unix.go enforces 0600 on unix.
func checkKeyMode(_ string) error {
	return nil
}
