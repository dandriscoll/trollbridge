package oplog

import (
	"io"
	"log/slog"
	"testing"
)

// BenchmarkHandler_Handle measures the per-record cost of the
// custom slog handler. Per 003-design Performance-architect F-P1,
// merging is gated on this staying under ~1µs/op on commodity
// hardware. If a future change pushes it above, redesign — likely
// by replacing the bespoke handler with slog.NewTextHandler and
// accepting the format change.
func BenchmarkHandler_Handle(b *testing.B) {
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)
	h := &textHandler{dest: &sharedWriter{w: io.Discard}, level: lv}
	lg := slog.New(h).With(
		"request_id", "8a74ad88-d151-4b83-bcfa-4890e255b436",
		"identity", "alice",
		"method", "GET",
		"scheme", "https",
		"host", "api.example.com",
		"port", 443,
	)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lg.Info("forwarded",
			"phase", PhaseForwarded,
			"status", 200,
			"bytes", int64(1024),
			"latency_ms", int64(7),
		)
	}
}

// BenchmarkHandler_HandleSimple — bare-minimum record, no With
// chain. Lower-bound on the formatter's cost.
func BenchmarkHandler_HandleSimple(b *testing.B) {
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)
	h := &textHandler{dest: &sharedWriter{w: io.Discard}, level: lv}
	lg := slog.New(h)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lg.Info("rules reloaded", "version", "abc123")
	}
}
