package advisor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// recordingLogger captures Warn invocations for assertion. Matches
// the advisor.Logger interface (just Warn).
type recordingLogger struct {
	calls []logCall
}

type logCall struct {
	msg  string
	args []any
}

func (r *recordingLogger) Warn(msg string, args ...any) {
	r.calls = append(r.calls, logCall{msg: msg, args: args})
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
	_, _ = s.Classify(context.Background(), req, "v1", nil, nil, nil)

	if len(log.calls) != 1 {
		t.Fatalf("want 1 Warn call, got %d", len(log.calls))
	}
	if !hasArg(log.calls[0].args, "event", "advisor_wire_fail") {
		t.Errorf("expected event=advisor_wire_fail; got args=%v", log.calls[0].args)
	}
	if !hasArg(log.calls[0].args, "request_id", "req-wire-1") {
		t.Errorf("expected request_id arg; got %v", log.calls[0].args)
	}
}

// TestService_SchemaFailure_EmitsLayerTaggedEvent closes #25 for
// the schema-layer branch.
func TestService_SchemaFailure_EmitsLayerTaggedEvent(t *testing.T) {
	log := &recordingLogger{}
	prov := &failingProvider{err: errors.Join(ErrAdvisorSchema, errors.New("missing tool_use block"))}
	s := newServiceForFailureTest(prov, log)

	req := &types.RequestEvent{ID: "req-schema-1", Method: "GET", Host: "example.com", Path: "/", Headers: nil}
	_, _ = s.Classify(context.Background(), req, "v1", nil, nil, nil)

	if len(log.calls) != 1 {
		t.Fatalf("want 1 Warn call, got %d", len(log.calls))
	}
	if !hasArg(log.calls[0].args, "event", "advisor_schema_fail") {
		t.Errorf("expected event=advisor_schema_fail; got args=%v", log.calls[0].args)
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
	_, _ = s.Classify(context.Background(), req, "v1", nil, nil, nil)

	if len(log.calls) != 1 || !hasArg(log.calls[0].args, "event", "advisor_unknown_fail") {
		t.Errorf("expected one advisor_unknown_fail Warn; got %v", log.calls)
	}
}

// TestService_NoLogger_DoesNotPanic asserts the nil-safety of
// SetLogger never being called.
func TestService_NoLogger_DoesNotPanic(t *testing.T) {
	prov := &failingProvider{err: ErrAdvisorWire}
	s := New(Config{Enabled: true, KnownModifiers: map[string]bool{}, Timeout: time.Second, CacheTTL: time.Minute}, prov)
	// no SetLogger call
	req := &types.RequestEvent{ID: "req-y", Method: "GET", Host: "y.example", Path: "/", Headers: nil}
	_, _ = s.Classify(context.Background(), req, "v1", nil, nil, nil)
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
