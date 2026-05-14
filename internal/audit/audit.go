// Package audit writes the structured JSONL audit log. Async
// buffered with bounded overflow behavior per DESIGN.md §15.4.
package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// Entry is one audit-log record. Fields per DESIGN.md §15.2.
type Entry struct {
	Timestamp           string `json:"timestamp"`
	TrollbridgeVersion   string `json:"trollbridge_version"`
	AuditSchemaVersion  int    `json:"audit_schema_version"`

	RequestID  string `json:"request_id"`
	SessionID  string `json:"session_id"`
	IdentityID string `json:"identity_id"`
	ClientAddr string `json:"client_addr"`

	Method string `json:"method"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Path   string `json:"path"`
	QueryRedacted string `json:"query_redacted"`

	Decision        string `json:"decision"`
	DecisionSource  string `json:"decision_source"`
	RuleID          string `json:"rule_id"`
	RuleSetVersion  string `json:"rule_set_version"`
	LLMAdvisorID    string `json:"llm_advisor_id"`
	LLMConfidence   string `json:"llm_confidence"`
	LLMInputHash    string `json:"llm_input_hash"`
	Reason          string `json:"reason"`

	RedactionApplied   bool `json:"redaction_applied"`
	RedactedFieldCount int  `json:"redacted_field_count"`

	BodyInspectionStatus string `json:"body_inspection_status"`
	RequestBodySample    string `json:"request_body_sample"`

	ResponseStatus    int   `json:"response_status"`
	ResponseSizeBytes int64 `json:"response_size_bytes"`
	LatencyMS         int64 `json:"latency_ms"`

	Error string `json:"error"`

	// TLS-failure diagnostics. Populated only when the entry
	// records a TLS handshake failure (either client → proxy or
	// proxy → origin); omitted otherwise so successful requests
	// remain compact in the JSONL log. See
	// internal/server/tls_diag.go for the source of TLSErrorCategory.
	TLSErrorCategory       string   `json:"tls_error_category,omitempty"`
	TLSSNI                 string   `json:"tls_sni,omitempty"`
	TLSALPNOffered         []string `json:"tls_alpn_offered,omitempty"`
	TLSVersionsOffered     []string `json:"tls_versions_offered,omitempty"`
	TLSCipherSuitesOffered []string `json:"tls_cipher_suites_offered,omitempty"`

	// Post-signal resolution fields (closes #97). Set only on the
	// follow-up audit entry written when a held request's eventual
	// resolution arrives after the consumer was signaled (471) by
	// approvals.signal_after_seconds. The matching original entry
	// (with `decision: ask_user_signaled`) carries the same
	// request_id, so an operator can correlate by grep.
	PostSignalResolution bool `json:"post_signal_resolution,omitempty"`
	SignalAfterSeconds   int  `json:"signal_after_seconds,omitempty"`
}

// OverflowMode controls how the logger reacts when its buffer is
// full and the caller emits another Entry.
type OverflowMode string

const (
	OverflowDeny  OverflowMode = "deny"
	OverflowDrop  OverflowMode = "drop"
	OverflowBlock OverflowMode = "block"
)

// Level controls which entries the Logger emits. The zero value is
// LevelAll so an audit.Logger constructed without SetLevel preserves
// the original "every entry is written" behavior (#113).
type Level int

const (
	// LevelAll emits every entry the caller writes. Default.
	LevelAll Level = iota
	// LevelDecisions emits only entries whose DecisionSource is
	// a human (approval queue, including timeout) or the LLM
	// advisor. Static-policy auto-decisions (rule, default, allow
	// list, deny list) are dropped at enqueue. Failure and error
	// entries — TLS handshake failures, transport errors, body-read
	// failures — likewise carry a non-human/LLM DecisionSource and
	// are not retained: this level is decisions only, by design,
	// not "decisions plus security events".
	LevelDecisions
	// LevelNone emits nothing. The Logger silently drops every
	// entry passed to Write.
	LevelNone
)

// ParseLevel parses an operator-facing level string into a Level.
// Accepts "all", "decisions", "none". Empty string defaults to
// LevelAll (so a config omitting the key preserves current
// behavior). Unknown values produce a clear error naming the legal
// set.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "", "all":
		return LevelAll, nil
	case "decisions":
		return LevelDecisions, nil
	case "none":
		return LevelNone, nil
	}
	return LevelAll, fmt.Errorf("audit: unknown level %q (want one of: none, decisions, all)", s)
}

// String renders a Level back to its operator-facing string form.
func (l Level) String() string {
	switch l {
	case LevelNone:
		return "none"
	case LevelDecisions:
		return "decisions"
	default:
		return "all"
	}
}

// Logger is an async-buffered JSONL writer.
type Logger struct {
	path     string
	overflow OverflowMode

	ch       chan Entry
	closed   atomic.Bool
	wg       sync.WaitGroup
	stopCh   chan struct{}

	droppedCounter atomic.Int64

	opLog atomic.Pointer[slog.Logger]

	// level is the operator-controlled emission filter (#113).
	// Stored as int32 for lock-free atomic reads on the hot Write
	// path; the zero value maps to LevelAll so a Logger built
	// without SetLevel preserves prior behavior.
	level atomic.Int32
}

// SetOpLog wires the operational logger so that JSON-encode
// failures inside the writer goroutine surface on the same stream
// the operator is tailing. Safe to call before or after Write.
func (l *Logger) SetOpLog(lg *slog.Logger) { l.opLog.Store(lg) }

// SetLevel updates the emission filter. Safe to call concurrently
// with Write — the next entry observes the new level.
func (l *Logger) SetLevel(lvl Level) { l.level.Store(int32(lvl)) }

// Level returns the current emission filter.
func (l *Logger) Level() Level { return Level(l.level.Load()) }

// New opens (or creates with mode 0640) the audit-log file and
// returns a Logger. bufSize bounds the in-memory queue.
func New(path string, bufSize int, overflow OverflowMode) (*Logger, error) {
	if path == "" {
		return nil, fmt.Errorf("audit: empty path")
	}
	if bufSize <= 0 {
		bufSize = 1024
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("audit: mkdir log dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit: open log: %w", err)
	}
	l := &Logger{
		path:     path,
		overflow: overflow,
		ch:       make(chan Entry, bufSize),
		stopCh:   make(chan struct{}),
	}
	l.wg.Add(1)
	go l.writeLoop(f)
	return l, nil
}

// Write enqueues an Entry. Returns nil on enqueue, an error if
// overflow=deny and the buffer is full. Entries that the current
// Level filters out are dropped here (before enqueue) and return
// nil — they are not a caller error and they do not consume a
// buffer slot.
func (l *Logger) Write(e Entry) error {
	if l.closed.Load() {
		return fmt.Errorf("audit: logger closed")
	}
	// Level filter (#113). Drop before enqueue so the buffer
	// budget is not spent on entries that will never be written.
	switch Level(l.level.Load()) {
	case LevelNone:
		return nil
	case LevelDecisions:
		if !types.DecisionSource(e.DecisionSource).IsHumanOrLLM() {
			return nil
		}
	}
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if e.AuditSchemaVersion == 0 {
		e.AuditSchemaVersion = 1
	}
	switch l.overflow {
	case OverflowBlock:
		l.ch <- e
		return nil
	case OverflowDrop:
		select {
		case l.ch <- e:
		default:
			l.droppedCounter.Add(1)
		}
		return nil
	default: // OverflowDeny
		select {
		case l.ch <- e:
			return nil
		default:
			return fmt.Errorf("audit: buffer full")
		}
	}
}

// Dropped returns the number of dropped entries (for OverflowDrop).
func (l *Logger) Dropped() int64 { return l.droppedCounter.Load() }

// Close flushes the buffer and closes the underlying file.
func (l *Logger) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	close(l.ch)
	l.wg.Wait()
	return nil
}

func (l *Logger) writeLoop(f *os.File) {
	defer l.wg.Done()
	defer f.Close()
	enc := json.NewEncoder(f)
	// Disable HTML escaping so redaction markers like "<redacted>"
	// land as literal angle brackets in the audit log; this is a
	// JSONL log, not HTML embedding.
	enc.SetEscapeHTML(false)
	for e := range l.ch {
		if err := enc.Encode(e); err != nil {
			if lg := l.opLog.Load(); lg != nil {
				lg.Error("audit encode failure",
					"event", "audit_encode_failure",
					"request_id", e.RequestID,
					"error", err.Error())
			} else {
				fmt.Fprintf(os.Stderr, "audit: encode failed: %v\n", err)
			}
		}
	}
}
