//go:build !windows

package tui

import "syscall"

// raiseSIGTSTP stops this process the way the terminal driver would if
// the TUI weren't in raw mode (#176). In raw mode the kernel delivers
// ^Z as a plain 0x1a byte instead of generating SIGTSTP, so the TUI
// raises it explicitly. The signal is sent to our own process group
// (pid 0 = caller's group) so a wrapping shell job stops as a unit and
// `fg` brings the whole group back. The call returns once the process
// is resumed with SIGCONT (default disposition: continue).
func raiseSIGTSTP() {
	_ = syscall.Kill(0, syscall.SIGTSTP)
}
