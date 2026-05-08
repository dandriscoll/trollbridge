// Package oplog builds trollbridge's operational logger — a leveled
// *slog.Logger writing to stderr or a file. The audit log is the
// structured record of decisions; this is the running-process
// narrative the operator reads to answer "what is trollbridge
// doing right now?". See DESIGN.md §15.1.
package oplog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// StderrSink is the sentinel value of `logging.operational_path`
// that means "write to stderr." Any other value is a filesystem
// path.
const StderrSink = "stderr"

// ParseLevel resolves a level string (case-insensitive) to a
// slog.Level. The empty string returns slog.LevelInfo. Unknown
// values return an error naming the valid set.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("invalid log level %q; valid: debug, info, warn, error", s)
}

// New constructs the operational logger.
//
//   - path: StderrSink ("stderr") to write to os.Stderr; otherwise a
//     filesystem path opened append-only with mode 0640 (parent dir
//     mkdir 0750), mirroring the audit logger's file discipline.
//   - level: pointer-to-LevelVar so callers can mutate at runtime
//     (a future SIGUSR1 hook); pass nil to use a fixed Info level.
//
// On file-open failure New returns the underlying error — callers
// fail closed at startup.
func New(path string, level *slog.LevelVar) (*slog.Logger, error) {
	if level == nil {
		lv := new(slog.LevelVar)
		lv.Set(slog.LevelInfo)
		level = lv
	}
	var sink io.Writer
	if path == "" || path == StderrSink {
		sink = os.Stderr
	} else {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, fmt.Errorf(
				"open operational log failed: cannot create parent directory %s: %w; "+
					"fix: ensure the parent directory exists and is writable by the trollbridge user",
				filepath.Dir(path), err)
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, fmt.Errorf(
				"open operational log failed: %s: %w; "+
					"fix: ensure the file path is writable by the trollbridge user, or set logging.operational_path: stderr",
				path, err)
		}
		sink = f
	}
	h := &textHandler{w: sink, level: level}
	return slog.New(h), nil
}

// textHandler emits "<ts> <LEVEL> trollbridge: <msg> [k=v ...]" lines.
// Greppable, sort-friendly, recognizable to operators familiar with
// the prior `log.LstdFlags` format. We keep the implementation small
// (no nested groups, no source positions) — operators who want the
// full slog feature surface can swap in slog.NewTextHandler upstream.
type textHandler struct {
	w     io.Writer
	level *slog.LevelVar
	mu    sync.Mutex
	attrs []slog.Attr
}

func (h *textHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *textHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &textHandler{w: h.w, level: h.level, attrs: merged}
}

// WithGroup is required by the interface but trollbridge doesn't
// currently use group semantics; we flatten by ignoring the prefix.
func (h *textHandler) WithGroup(_ string) slog.Handler { return h }

func (h *textHandler) Handle(_ context.Context, r slog.Record) error {
	var b []byte
	b = r.Time.UTC().AppendFormat(b, time.RFC3339Nano)
	b = append(b, ' ')
	b = append(b, levelString(r.Level)...)
	b = append(b, ' ')
	b = append(b, "trollbridge: "...)
	b = append(b, r.Message...)
	for _, a := range h.attrs {
		b = appendAttr(b, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		b = appendAttr(b, a)
		return true
	})
	b = append(b, '\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(b)
	return err
}

func levelString(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERROR"
	case l >= slog.LevelWarn:
		return "WARN"
	case l >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}

func appendAttr(b []byte, a slog.Attr) []byte {
	if a.Key == "" {
		return b
	}
	b = append(b, ' ')
	b = append(b, a.Key...)
	b = append(b, '=')
	return appendValue(b, a.Value)
}

func appendValue(b []byte, v slog.Value) []byte {
	v = v.Resolve()
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		if needsQuoting(s) {
			return strconv.AppendQuote(b, s)
		}
		return append(b, s...)
	case slog.KindInt64:
		return strconv.AppendInt(b, v.Int64(), 10)
	case slog.KindUint64:
		return strconv.AppendUint(b, v.Uint64(), 10)
	case slog.KindFloat64:
		return strconv.AppendFloat(b, v.Float64(), 'g', -1, 64)
	case slog.KindBool:
		return strconv.AppendBool(b, v.Bool())
	case slog.KindDuration:
		return append(b, v.Duration().String()...)
	case slog.KindTime:
		return v.Time().UTC().AppendFormat(b, time.RFC3339Nano)
	case slog.KindAny:
		s := fmt.Sprint(v.Any())
		if needsQuoting(s) {
			return strconv.AppendQuote(b, s)
		}
		return append(b, s...)
	}
	return b
}

func needsQuoting(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if r <= ' ' || r == '"' || r == '=' || r == '\\' {
			return true
		}
	}
	return false
}
