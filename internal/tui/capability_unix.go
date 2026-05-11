//go:build !windows

package tui

// enableConsoleVT is a no-op on POSIX terminals — they support ANSI
// escape sequences (alt-screen, color, cursor positioning) by default.
// The Windows variant in capability_windows.go calls SetConsoleMode
// to opt into virtual-terminal processing and fails loudly when the
// host terminal does not support it (closes #61).
func enableConsoleVT() error { return nil }
