package advisor

import "sync/atomic"

// Stats are process-lifetime counters for the LLM advisor (#137):
// how often it was consulted, how many calls produced a usable
// classification, how many fell back (no usable verdict), how many
// failed by error class, plus a latency histogram of the classify
// round-trip. All counters are atomic — Classify runs concurrently
// from many request goroutines.
//
// Invariant: Consulted == Classified + Fallback (every consult ends in
// exactly one of those; errors are counted under Fallback AND under the
// matching Err* class, since an error is one kind of fallback).
type Stats struct {
	Consulted  atomic.Int64
	Classified atomic.Int64
	Fallback   atomic.Int64
	ErrWire    atomic.Int64
	ErrSchema  atomic.Int64
	ErrUnknown atomic.Int64

	latency [len(latencyBucketsMS)]atomic.Int64
}

// latencyBucketsMS are the inclusive upper bounds (milliseconds) of the
// classify-latency histogram; the final bucket catches everything above
// the last bound (recorded at index len(bounds)).
var latencyBucketsMS = [...]int64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

func (s *Stats) recordLatency(ms int64) {
	for i, ub := range latencyBucketsMS {
		if ms <= ub {
			s.latency[i].Add(1)
			return
		}
	}
	s.latency[len(latencyBucketsMS)-1].Add(1) // overflow → last bucket (> last bound handled by index)
}

// LatencyBucket pairs a histogram bound with its count for the snapshot.
type LatencyBucket struct {
	LEMillis int64 `json:"le_ms"` // count of classifies completing in <= this many ms
	Count    int64 `json:"count"`
}

// StatsSnapshot is a plain (non-atomic) copy for JSON serialization.
type StatsSnapshot struct {
	Consulted  int64           `json:"consulted"`
	Classified int64           `json:"classified"`
	Fallback   int64           `json:"fallback"`
	ErrWire    int64           `json:"error_wire"`
	ErrSchema  int64           `json:"error_schema"`
	ErrUnknown int64           `json:"error_unknown"`
	Latency    []LatencyBucket `json:"classify_latency_ms"`
}

// Snapshot reads the live counters into a plain struct.
func (s *Stats) Snapshot() StatsSnapshot {
	if s == nil {
		return StatsSnapshot{}
	}
	out := StatsSnapshot{
		Consulted:  s.Consulted.Load(),
		Classified: s.Classified.Load(),
		Fallback:   s.Fallback.Load(),
		ErrWire:    s.ErrWire.Load(),
		ErrSchema:  s.ErrSchema.Load(),
		ErrUnknown: s.ErrUnknown.Load(),
	}
	for i, ub := range latencyBucketsMS {
		out.Latency = append(out.Latency, LatencyBucket{LEMillis: ub, Count: s.latency[i].Load()})
	}
	return out
}
