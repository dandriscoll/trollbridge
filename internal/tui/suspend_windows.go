//go:build windows

package tui

// raiseSIGTSTP is a no-op on Windows, which has no SIGTSTP/SIGCONT job
// control (#176). The `z` hotkey therefore does nothing on Windows; the
// suspend closure still restores and re-enters the terminal harmlessly.
func raiseSIGTSTP() {}
