package advisor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// recordingLogger captures Debug/Info/Warn invocations for
// assertion. Matches the advisor.Logger interface.
type recordingLogger struct {
	calls []logCall
}

type logCall struct {
	level string
	msg   string
	args  []any
}

func (r *recordingLogger) Debug(msg string, args ...any) {
	r.calls = append(r.calls, logCall{level: "debug", msg: msg, args: args})
}
func (r *recordingLogger) Info(msg string, args ...any) {
	r.calls = append(r.calls, logCall{level: "info", msg: msg, args: args})
}
func (r *recordingLogger) Warn(msg string, args ...any) {
	r.calls = append(r.calls, logCall{level: "warn", msg: msg, args: args})
}

// callsAtLevel returns only the calls recorded at the given level.
func (r *recordingLogger) callsAtLevel(level string) []logCall {
	out := []logCall{}
	for _, c := range r.calls {
		if c.level == level {
			out = append(out, c)
		}
	}
	return out
}

// failingProvider returns the supplied error from Classify.
type failingProvider struct{ err error }

func (f *failingProvider) Classify(ctx context.Context, in Input) (Output, error) {
	return Output{}, f.err
}

func newServiceForFailureTest(prov Provider, log Logger) *Service {
	s := New(Config{
		Enabled:        true,
		KnownModifiers: map[string]bool{},
		Timeout:        time.Second,
		CacheTTL:       time.Minute,
	}, prov)
	s.SetLogger(log)
	return s
}

// TestService_WireFailure_EmitsLayerTaggedEvent closes issue #25
// for the wire-layer branch.
func TestService_WireFailure_EmitsLayerTaggedEvent(t *testing.T) {
	log := &recordingLogger{}
	prov := &failingProvider{err: errors.Join(ErrAdvisorWire, errors.New("dial tcp: connect: connection refused"))}
	s := newServiceForFailureTest(prov, log)

	req := &types.RequestEvent{ID: "req-wire-1", Method: "GET", Host: "example.com", Path: "/", Headers: nil}
	_, _ = s.Classify(context.Background(), req, "v1", nil, nil)

	warnCalls := log.callsAtLevel("warn")
	if len(warnCalls) != 1 {
		t.Fatalf("want 1 Warn call, got %d (all calls=%v)", len(warnCalls), log.calls)
	}
	if !hasArg(warnCalls[0].args, "event", "advisor_wire_fail") {
		t.Errorf("expected event=advisor_wire_fail; got args=%v", warnCalls[0].args)
	}
	if !hasArg(warnCalls[0].args, "request_id", "req-wire-1") {
		t.Errorf("expected request_id arg; got %v", warnCalls[0].args)
	}
}

// TestService_SchemaFailure_EmitsLayerTaggedEvent closes #25 for
// the schema-layer branch.
func TestService_SchemaFailure_EmitsLayerTaggedEvent(t *testing.T) {
	log := &recordingLogger{}
	prov := &failingProvider{err: errors.Join(ErrAdvisorSchema, errors.New("missing tool_use block"))}
	s := newServiceForFailureTest(prov, log)

	req := &types.RequestEvent{ID: "req-schema-1", Method: "GET", Host: "example.com", Path: "/", Headers: nil}
	_, _ = s.Classify(context.Background(), req, "v1", nil, nil)

	warnCalls := log.callsAtLevel("warn")
	if len(warnCalls) != 1 {
		t.Fatalf("want 1 Warn call, got %d (all calls=%v)", len(warnCalls), log.calls)
	}
	if !hasArg(warnCalls[0].args, "event", "advisor_schema_fail") {
		t.Errorf("expected event=advisor_schema_fail; got args=%v", warnCalls[0].args)
	}
}

// TestService_UnknownFailure_FallsBackToUnknownEvent confirms an
// error that wraps neither sentinel still produces a Warn (so an
// operator debugging the path always sees something), tagged
// generically.
func TestService_UnknownFailure_FallsBackToUnknownEvent(t *testing.T) {
	log := &recordingLogger{}
	prov := &failingProvider{err: errors.New("opaque advisor failure")}
	s := newServiceForFailureTest(prov, log)

	req := &types.RequestEvent{ID: "req-x", Method: "GET", Host: "x.example", Path: "/", Headers: nil}
	_, _ = s.Classify(context.Background(), req, "v1", nil, nil)

	warnCalls := log.callsAtLevel("warn")
	if len(warnCalls) != 1 || !hasArg(warnCalls[0].args, "event", "advisor_unknown_fail") {
		t.Errorf("expected one advisor_unknown_fail Warn; got %v", warnCalls)
	}
}

// TestService_NoLogger_DoesNotPanic asserts the nil-safety of
// SetLogger never being called.
func TestService_NoLogger_DoesNotPanic(t *testing.T) {
	prov := &failingProvider{err: ErrAdvisorWire}
	s := New(Config{Enabled: true, KnownModifiers: map[string]bool{}, Timeout: time.Second, CacheTTL: time.Minute}, prov)
	// no SetLogger call
	req := &types.RequestEvent{ID: "req-y", Method: "GET", Host: "y.example", Path: "/", Headers: nil}
	_, _ = s.Classify(context.Background(), req, "v1", nil, nil)
	// Reaching here is the assertion.
}

// hasArg returns true when the structured-log args slice contains a
// key→value pair matching the supplied key/value (both as strings).
func hasArg(args []any, key, value string) bool {
	for i := 0; i+1 < len(args); i += 2 {
		k, _ := args[i].(string)
		v, _ := args[i+1].(string)
		if k == key && strings.Contains(v, value) {
			return true
		}
	}
	return false
}

// stubProvider returns a fixed Output, no error.
type stubProvider struct{ out Output }

func (s *stubProvider) Classify(ctx context.Context, in Input) (Output, error) {
	return s.out, nil
}

// TestService_LogsConsultedAndClassified closes #36 by asserting
// that an INFO `advisor_consulted` fires before the provider call
// and an INFO `advisor_classified` fires after a successful one.
func TestService_LogsConsultedAndClassified(t *testing.T) {
	log := &recordingLogger{}
	prov := &stubProvider{out: Output{
		Effect: "allow", Scope: "once", Confidence: "high",
	}}
	s := New(Config{
		Enabled:        true,
		KnownModifiers: map[string]bool{},
		Timeout:        time.Second,
		CacheTTL:       time.Minute,
	}, prov)
	s.SetLogger(log)

	req := &types.RequestEvent{ID: "req-ok-1", Method: "GET", Host: "example.com", Path: "/", IdentityID: "id-1"}
	_, _ = s.Classify(context.Background(), req, "v1", nil, nil)

	infoCalls := log.callsAtLevel("info")
	if len(infoCalls) != 2 {
		t.Fatalf("want 2 Info calls (consulted + classified), got %d (%v)", len(infoCalls), log.calls)
	}
	if !hasArg(infoCalls[0].args, "event", "advisor_consulted") {
		t.Errorf("first Info: expected event=advisor_consulted, got %v", infoCalls[0].args)
	}
	if !hasArg(infoCalls[0].args, "request_id", "req-ok-1") {
		t.Errorf("first Info: expected request_id=req-ok-1, got %v", infoCalls[0].args)
	}
	if !hasArg(infoCalls[1].args, "event", "advisor_classified") {
		t.Errorf("second Info: expected event=advisor_classified, got %v", infoCalls[1].args)
	}
	if !hasArg(infoCalls[1].args, "effect", "allow") {
		t.Errorf("second Info: expected effect=allow, got %v", infoCalls[1].args)
	}
}

// TestService_LogsConsultedButNotClassifiedOnFailure asserts that
// a wire failure produces consulted+warn but not classified.
func TestService_LogsConsultedButNotClassifiedOnFailure(t *testing.T) {
	log := &recordingLogger{}
	prov := &failingProvider{err: errors.Join(ErrAdvisorWire, errors.New("connect: refused"))}
	s := newServiceForFailureTest(prov, log)

	req := &types.RequestEvent{ID: "req-fail-1", Method: "GET", Host: "ex.com"}
	_, _ = s.Classify(context.Background(), req, "v1", nil, nil)

	infoCalls := log.callsAtLevel("info")
	if len(infoCalls) != 1 || !hasArg(infoCalls[0].args, "event", "advisor_consulted") {
		t.Errorf("expected one Info advisor_consulted before the wire failure, got %v", infoCalls)
	}
	warnCalls := log.callsAtLevel("warn")
	if len(warnCalls) != 1 || !hasArg(warnCalls[0].args, "event", "advisor_wire_fail") {
		t.Errorf("expected one Warn advisor_wire_fail, got %v", warnCalls)
	}
}

// TestHTTPClassifier_DebugWireResponseFires asserts that the
// HTTPClassifier emits a Debug `advisor_wire_response` record per
// Classify call when an OpLog is wired.
func TestHTTPClassifier_DebugWireResponseFires(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad request"}`))
	}))
	defer srv.Close()

	log := &recordingLogger{}
	tr, _ := TranslatorFor("anthropic", "")
	cli := &HTTPClassifier{
		Endpoint:   srv.URL,
		APIKey:     "ak",
		Model:      "claude",
		Translator: tr,
		OpLog:      log,
	}
	_, _ = cli.Classify(context.Background(), Input{Host: "x.example", Method: "GET", Path: "/"})

	debugCalls := log.callsAtLevel("debug")
	if len(debugCalls) != 1 {
		t.Fatalf("want 1 Debug call, got %d (%v)", len(debugCalls), log.calls)
	}
	if !hasArg(debugCalls[0].args, "event", "advisor_wire_response") {
		t.Errorf("event: %v", debugCalls[0].args)
	}
	if !hasArg(debugCalls[0].args, "url", srv.URL) {
		t.Errorf("url: %v", debugCalls[0].args)
	}
	if !hasArgInt(debugCalls[0].args, "status", 400) {
		t.Errorf("status: %v", debugCalls[0].args)
	}
	// 4xx body sample present.
	if !hasArg(debugCalls[0].args, "body_sample", "bad request") {
		t.Errorf("body_sample missing: %v", debugCalls[0].args)
	}
}

// hasArgInt mirrors hasArg for int values (status codes).
func hasArgInt(args []any, key string, want int) bool {
	for i := 0; i+1 < len(args); i += 2 {
		k, _ := args[i].(string)
		if k != key {
			continue
		}
		if v, ok := args[i+1].(int); ok && v == want {
			return true
		}
	}
	return false
}
