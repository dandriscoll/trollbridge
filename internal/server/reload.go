package server

import "github.com/dandriscoll/trollbridge/internal/reloadstatus"

// RecordReload writes the outcome of a hot-reload attempt to the
// server's reload tracker (closes #129). source is one of
// "config" | "rules" | "lists"; err is nil on success.
//
// Call sites: cmd/trollbridge/run.go's SIGHUP handler, the fsnotify
// watcher, and the console-pane OnReload callback. Each existing
// opLog.{Error,Info} for a reload event is paired with one
// RecordReload call so the operator-visible TUI badge stays in sync
// with the structured operational log.
//
// On the fsnotify cascade (lists → rules → config), the last call
// wins. If lists fails and we early-return, the tracker holds the
// lists-failure error. If everything succeeds, the final
// config-reload call clears the error.
func (s *Server) RecordReload(source string, err error) {
	s.reloadTracker.Record(source, err)
}

// ReloadStatus returns a snapshot of the most-recent hot-reload
// outcome. Safe for concurrent use; the returned value is not
// aliased.
//
// Wired into the control plane's /v1/rules response via
// SetReloadStatusProvider; the TUI's HTTP client parses the
// resulting JSON fields, and the in-process client calls this
// method directly. When LastError is non-empty the TUI renders
// a bold-red `␇ reload failed` badge in the approvals pane header.
func (s *Server) ReloadStatus() reloadstatus.Status {
	return s.reloadTracker.Get()
}
