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
}

// OverflowMode controls how the logger reacts when its buffer is
// full and the caller emits another Entry.
type OverflowMode string

const (
	OverflowDeny  OverflowMode = "deny"
	OverflowDrop  OverflowMode = "drop"
	OverflowBlock OverflowMode = "block"
)

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
}

// SetOpLog wires the operational logger so that JSON-encode
// failures inside the writer goroutine surface on the same stream
// the operator is tailing. Safe to call before or after Write.
func (l *Logger) SetOpLog(lg *slog.Logger) { l.opLog.Store(lg) }

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
// overflow=deny and the buffer is full.
func (l *Logger) Write(e Entry) error {
	if l.closed.Load() {
		return fmt.Errorf("audit: logger closed")
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
