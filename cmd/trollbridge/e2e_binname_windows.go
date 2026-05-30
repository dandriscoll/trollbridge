//go:build e2e && windows

package main

// e2eBinSuffix is appended to the e2e harness's compiled binary
// path. Windows requires the .exe suffix for os/exec to find the
// binary by absolute path (the executable-not-found-in-%PATH%
// failure shape the e2e suite hit in #163 Phase 1 observation).
// Build-tagged per trollbridge insight #16.
const e2eBinSuffix = ".exe"
