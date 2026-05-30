//go:build e2e && !windows

package main

// e2eBinSuffix is appended to the e2e harness's compiled binary
// path. On unix-family targets this is empty; on windows the
// executable must end in .exe (see e2e_binname_windows.go). Build-
// tagged per trollbridge insight #16 (no runtime.GOOS branches for
// OS-coupled code).
const e2eBinSuffix = ""
