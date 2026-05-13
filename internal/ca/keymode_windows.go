//go:build windows

package ca

// checkKeyMode is a no-op on Windows today. POSIX permission bits are
// not the protection mechanism here — os.Stat reports 0o666 for any
// file and chmod is best-effort — and NTFS ACLs govern access
// instead. The unix variant in keymode_unix.go enforces 0600 on unix.
//
// Today's Windows users run trollbridge in user-mode (see
// `update.go`'s "Auto-update is not yet supported on Windows" branch
// and `init.go::printDaemonNextSteps`'s Windows refusal). User-mode
// trollbridge runs under the operator's own account; per-user
// filesystem ACLs in `%USERPROFILE%` already gate access to keys
// without explicit DACL surgery.
//
// The multi-user exposure that warrants a real DACL implementation
// only materializes when daemon-mode-on-Windows lands (Windows-
// service integration + restricted service account). At that point
// this function MUST grow:
//
//  1. apply: after writePEM creates the key, set a DACL via
//     `windows.SetNamedSecurityInfo` granting full control to the
//     trollbridge service SID and nothing else; protect the DACL
//     against inheritance.
//  2. check: on Load, read the DACL via
//     `windows.GetNamedSecurityInfo`; refuse to load if any ACE
//     grants Everyone, BUILTIN\Users, or BUILTIN\Authenticated
//     Users access.
//
// Tracked under issue #101 (Windows hardening); blocked on the
// daemon-mode-Windows workstream landing first.
func checkKeyMode(_ string) error {
	return nil
}
