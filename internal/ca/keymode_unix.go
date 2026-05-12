//go:build !windows

package ca

import (
	"fmt"
	"os"
)

// checkKeyMode enforces 0600 on the key file. POSIX permission bits
// are the protection mechanism on unix; running this check on Windows
// is a no-op (see keymode_windows.go) because NTFS ACLs — not POSIX
// modes — gate access, and os.Stat reports 0o666 for any file there.
func checkKeyMode(keyPath string) error {
	info, err := os.Stat(keyPath)
	if err != nil {
		return nil
	}
	if mode := info.Mode().Perm(); mode > 0o600 {
		return fmt.Errorf("ca load: key %s has mode %o; refuse to load (must be 0600)", keyPath, mode)
	}
	return nil
}
