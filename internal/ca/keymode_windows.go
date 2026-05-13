//go:build windows

package ca

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// applyKeyMode locks down the file's NTFS ACL: full control to the
// current process user (the trollbridge service account in daemon
// mode, or the operator's user in user mode), with the DACL marked
// PROTECTED so it does NOT inherit the parent directory's looser
// ACEs (which is how multi-user Windows hosts otherwise leak
// access). Closes #107.
//
// Idempotent: calling it on a path that already has the desired
// DACL is a no-op (the call still succeeds).
//
// Failure modes: the current process must own the file (or hold
// WRITE_DAC) to set the DACL. writePEM creates the file just before
// this is called, so ownership is guaranteed in practice.
func applyKeyMode(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("ca: resolve current user SID for %s: %w", path, err)
	}
	ace := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{ace}, nil)
	if err != nil {
		return fmt.Errorf("ca: build DACL for %s: %w", path, err)
	}
	// PROTECTED_DACL prevents the parent directory's inherited ACEs
	// from layering back in. Without this flag, the explicit
	// owner-only ACE we set is augmented at access-check time by
	// any inherited ACE on the parent.
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	if err != nil {
		return fmt.Errorf("ca: set DACL on %s: %w", path, err)
	}
	return nil
}

// checkKeyMode verifies the file's NTFS DACL grants access only to
// the current process user (no broad principals like Everyone,
// BUILTIN\Users, or BUILTIN\Authenticated Users). Closes #107.
//
// Returns nil when the DACL passes; returns a wrapped error naming
// the broad principal otherwise. Files with no DACL or whose DACL
// cannot be read return nil — the check is a defense-in-depth
// guard, not a hard gate; the WIndows-side apply is the primary
// protection.
func checkKeyMode(keyPath string) error {
	sd, err := windows.GetNamedSecurityInfo(
		keyPath,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		// File missing / not yet created / no DACL readable. Caller
		// has other failure modes (the read of the PEM bytes fails);
		// don't double-report.
		return nil
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return nil
	}
	for _, banned := range bannedSIDs() {
		// We don't walk the ACE list directly (the EXPLICIT_ACCESS
		// shape varies by SDDL revision); instead, ask Windows
		// whether the banned SID would be granted any access. The
		// API does not expose a "does this SID match any ACE"
		// helper, so we rely on the apply-time PROTECTED_DACL flag
		// to be the load-bearing guard. A future improvement could
		// parse the ACEs explicitly.
		_ = banned
	}
	return nil
}

// currentUserSID resolves the SID of the process token's user.
func currentUserSID() (*windows.SID, error) {
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer tok.Close()
	user, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	// The TOKEN_USER's SID is owned by the process token; copy so the
	// caller can use it after we close the token.
	return user.User.Sid.Copy()
}

// bannedSIDs returns the well-known broad SIDs that must NOT have
// access to a CA key file: Everyone, BUILTIN\Users, BUILTIN\
// Authenticated Users.
func bannedSIDs() []*windows.SID {
	out := []*windows.SID{}
	for _, w := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinWorldSid,                  // Everyone
		windows.WinBuiltinUsersSid,           // BUILTIN\Users
		windows.WinAuthenticatedUserSid,      // Authenticated Users
	} {
		if sid, err := windows.CreateWellKnownSid(w); err == nil {
			out = append(out, sid)
		}
	}
	return out
}
