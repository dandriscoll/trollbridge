package approvals

import (
	"sync"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// TestResolveByAdvisor_DoesNotFirePersistCb_Allow pins alignment
// principle §1 (docs/alignment-principles.md) at the load-bearing
// layer (closes #193): the LLM advisor's allow verdict must release
// the hold without writing the URL to lists.allow. PersistCb is
// the daemon's hook for "this decision should mutate the operator's
// list YAML"; only operator-driven approve/deny may fire it. An
// advisor-driven resolve is a single-request decision and must
// never touch the persistent list.
//
// Pre-fix behavior: queue.go ResolveByAdvisor called q.persistCb
// unconditionally with source="llm-advisor".
// Post-fix behavior: ResolveByAdvisor never calls persistCb.
func TestResolveByAdvisor_DoesNotFirePersistCb_Allow(t *testing.T) {
	q := New(8, time.Minute, "deny")
	var (
		mu    sync.Mutex
		calls []types.Effect
	)
	q.SetDecisionPersist(func(_ *types.RequestEvent, e types.Effect, _ string) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, e)
	})
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	if !q.ResolveByAdvisor(id, types.Decision{Effect: types.EffectAllow, Source: types.SourceLLMAdvisor}) {
		t.Fatal("ResolveByAdvisor returned false unexpectedly")
	}
	// Drain so the hold's resolveCh isn't blocked indefinitely (matches
	// the holdAndWait shape).
	<-ch
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 0 {
		t.Fatalf("persistCb fired %d times after an LLM-advisor Allow; want 0 (LLM must not write to lists). calls=%v", len(calls), calls)
	}
}

// TestResolveByAdvisor_DoesNotFirePersistCb_Deny is the symmetric
// case for deny (closes #193). The advisor's deny must not write
// to lists.deny.
func TestResolveByAdvisor_DoesNotFirePersistCb_Deny(t *testing.T) {
	q := New(8, time.Minute, "deny")
	var (
		mu    sync.Mutex
		calls []types.Effect
	)
	q.SetDecisionPersist(func(_ *types.RequestEvent, e types.Effect, _ string) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, e)
	})
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	if !q.ResolveByAdvisor(id, types.Decision{Effect: types.EffectDeny, Source: types.SourceLLMAdvisor}) {
		t.Fatal("ResolveByAdvisor returned false unexpectedly")
	}
	<-ch
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 0 {
		t.Fatalf("persistCb fired %d times after an LLM-advisor Deny; want 0 (LLM must not write to lists). calls=%v", len(calls), calls)
	}
}

// TestResolveByAdvisor_StillResolvesHold pins the legitimate effect
// of the call (closes #193): ResolveByAdvisor still releases the
// hold (the request can proceed or be denied per the advisor's
// verdict) — only the persist side-effect is removed.
func TestResolveByAdvisor_StillResolvesHold(t *testing.T) {
	q := New(8, time.Minute, "deny")
	q.SetDecisionPersist(func(_ *types.RequestEvent, _ types.Effect, _ string) {})
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	if !q.ResolveByAdvisor(id, types.Decision{Effect: types.EffectAllow, Source: types.SourceLLMAdvisor}) {
		t.Fatal("ResolveByAdvisor returned false; the hold should resolve")
	}
	select {
	case d := <-ch:
		if d.Effect != types.EffectAllow {
			t.Errorf("resolved effect = %v, want EffectAllow", d.Effect)
		}
		if d.Source != types.SourceLLMAdvisor {
			t.Errorf("resolved source = %v, want SourceLLMAdvisor (the audit log needs this)", d.Source)
		}
	case <-time.After(time.Second):
		t.Fatal("hold did not resolve after ResolveByAdvisor; the legitimate effect was lost")
	}
}

// TestResolveByAdvisor_OperatorApproveStillPersists pins the
// complement (closes #193): when the operator approves a hold
// (source="tui" or "attach"), persistCb still fires — only the
// LLM-driven path is silenced.
func TestResolveByAdvisor_OperatorApproveStillPersists(t *testing.T) {
	q := New(8, time.Minute, "deny")
	var (
		mu    sync.Mutex
		calls []string
	)
	q.SetDecisionPersist(func(_ *types.RequestEvent, _ types.Effect, source string) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, source)
	})
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	if !q.Approve(id, "rule-id", "tui") {
		t.Fatal("operator Approve returned false unexpectedly")
	}
	<-ch
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("operator Approve did not fire persistCb; calls=%v", calls)
	}
	if calls[0] != "tui" {
		t.Errorf("persistCb source = %q, want %q", calls[0], "tui")
	}
}
