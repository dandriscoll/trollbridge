package advisor

import (
	"context"
	"testing"
)

// TestStats_ConsultClassifyFallbackError pins #137: the advisor counters
// track each Classify outcome by class, and the invariant
// consulted == classified + fallback holds.
func TestStats_ConsultClassifyFallbackError(t *testing.T) {
	// Two confident allows → 2 classified.
	allow := &MockProvider{Output: Output{Effect: "allow", Confidence: "high", Reason: "ok"}}
	s := New(Config{Enabled: true, ConfidenceFloor: "medium"}, allow)
	s.Classify(context.Background(), newReq(), "v1", nil, nil)
	// Same request again hits the cache (no second consult).
	s.Classify(context.Background(), newReq(), "v1", nil, nil)

	st := s.Stats().Snapshot()
	if st.Consulted != 1 {
		t.Errorf("consulted = %d, want 1 (second call is cached)", st.Consulted)
	}
	if st.Classified != 1 {
		t.Errorf("classified = %d, want 1", st.Classified)
	}
	if st.Fallback != 0 {
		t.Errorf("fallback = %d, want 0", st.Fallback)
	}

	// Low confidence → fallback (consulted, but ask_user).
	low := &MockProvider{Output: Output{Effect: "allow", Confidence: "low"}}
	s2 := New(Config{Enabled: true, ConfidenceFloor: "high"}, low)
	s2.Classify(context.Background(), newReq(), "v1", nil, nil)
	st2 := s2.Stats().Snapshot()
	if st2.Consulted != 1 || st2.Classified != 0 || st2.Fallback != 1 {
		t.Errorf("low-confidence: consulted/classified/fallback = %d/%d/%d, want 1/0/1",
			st2.Consulted, st2.Classified, st2.Fallback)
	}

	// Malformed effect → validation fallback.
	bad := &MockProvider{Output: Output{Effect: "blammo", Confidence: "high"}}
	s3 := New(Config{Enabled: true, ConfidenceFloor: "medium"}, bad)
	s3.Classify(context.Background(), newReq(), "v1", nil, nil)
	if st3 := s3.Stats().Snapshot(); st3.Fallback != 1 || st3.Classified != 0 {
		t.Errorf("malformed: classified/fallback = %d/%d, want 0/1", st3.Classified, st3.Fallback)
	}

	// Disabled advisor is never consulted.
	off := New(Config{Enabled: false}, nil)
	off.Classify(context.Background(), newReq(), "v1", nil, nil)
	if st4 := off.Stats().Snapshot(); st4.Consulted != 0 {
		t.Errorf("disabled consulted = %d, want 0", st4.Consulted)
	}
}

// TestStats_ErrorClassesAndLatency pins that provider errors are counted
// by class and that a classify records exactly one latency bucket.
func TestStats_ErrorClassesAndLatency(t *testing.T) {
	wire := &failingProvider{err: ErrAdvisorWire}
	s := New(Config{Enabled: true, Timeout: 0}, wire)
	s.Classify(context.Background(), newReq(), "v1", nil, nil)
	st := s.Stats().Snapshot()
	if st.ErrWire != 1 {
		t.Errorf("error_wire = %d, want 1", st.ErrWire)
	}
	if st.Fallback != 1 {
		t.Errorf("error also counts as fallback: got %d, want 1", st.Fallback)
	}
	// An errored consult records no latency (no clean round-trip).
	var total int64
	for _, b := range st.Latency {
		total += b.Count
	}
	if total != 0 {
		t.Errorf("errored consult recorded %d latency samples, want 0", total)
	}

	// A clean classify records exactly one latency sample.
	ok := &MockProvider{Output: Output{Effect: "allow", Confidence: "high"}}
	s2 := New(Config{Enabled: true, ConfidenceFloor: "medium"}, ok)
	s2.Classify(context.Background(), newReq(), "v1", nil, nil)
	var total2 int64
	for _, b := range s2.Stats().Snapshot().Latency {
		total2 += b.Count
	}
	if total2 != 1 {
		t.Errorf("clean classify latency samples = %d, want 1", total2)
	}
}
