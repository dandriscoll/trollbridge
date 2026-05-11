//go:build windows

package tui

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// enableConsoleVT opts into ENABLE_VIRTUAL_TERMINAL_PROCESSING on
// the Windows console handle so the TUI's ANSI escapes render
// instead of leaking as literal characters. Modern Windows Terminal
// and Win10 1809+ cmd.exe support it; legacy hosts fail here with
// an actionable error so the operator sees a readable message
// before the alt-screen mutates state (closes #61).
func enableConsoleVT() error {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return fmt.Errorf("trollbridge ui: cannot get stdout handle: %w", err)
	}
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return fmt.Errorf(
			"trollbridge ui: this stream is not a Windows console; "+
				"fix: run with --no-console for the headless path: %w", err)
	}
	if err := windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return fmt.Errorf(
			"trollbridge ui: cannot enable ANSI virtual-terminal mode "+
				"(Windows Terminal or Win10 1809+ required); "+
				"fix: run with --no-console or switch to Windows Terminal: %w", err)
	}
	return nil
}
