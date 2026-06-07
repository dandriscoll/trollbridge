package oplog

// Event-name constants for the operational log's `event=` field.
// Centralized so call sites cannot drift on the spelling.
const (
	EventStartup                  = "startup"
	EventShutdown                 = "shutdown"
	EventConfigLoaded             = "config_loaded"
	EventConfigLoadFailure        = "config_load_failure"
	// EventStartupFailure fires when the daemon failed to construct
	// after the operational log was open — `policy.NewEngine`,
	// `audit.New`, server construction, and inline-list parse failures
	// (closes #134). Sibling of EventConfigLoadFailure (#128), which
	// covers the *pre*-opLog failures. Carries a `stage` attribute
	// naming the construction step that failed (`policy` / `audit` /
	// `audit_level` / `server` / `lists`).
	EventStartupFailure           = "startup_failure"
	EventListening                = "listening"
	EventControlListening         = "control_listening"
	EventRuleReload               = "rule_reload"
	EventRuleReloadFailure        = "rule_reload_failure"
	EventAllowlistReload          = "allowlist_reload"
	EventAllowlistReloadFailure   = "allowlist_reload_failure"
	EventDenylistReload           = "denylist_reload"
	EventDenylistReloadFailure    = "denylist_reload_failure"
	EventForwardError             = "forward_error"
	EventBadRequest               = "bad_request"
	EventInterceptError              = "intercept_error"
	EventInterceptHandshakeFail      = "intercept_handshake_failure"
	EventInterceptUpstreamTLSFail    = "intercept_upstream_tls_failure"
	EventAuditWriteFailure        = "audit_write_failure"
	EventAuditEncodeFailure       = "audit_encode_failure"
	EventControlPlaneError        = "control_plane_error"
	EventOperatorUIError          = "operator_ui_error"

	// Ask-case lifecycle events. INFO-level for state transitions an
	// operator should see by default (no --verbose); WARN for refusal
	// states. Closes #36.
	EventRequestHeld      = "request_held"      // INFO; holdAndWait after Enqueue success
	EventRequestCoalesced = "request_coalesced" // INFO; #206 — identical request attached to an existing pending hold instead of a new row
	EventHoldApproved   = "hold_approved"    // INFO; Queue.Approve
	EventHoldDenied     = "hold_denied"      // INFO; Queue.Deny
	EventHoldTimedOut   = "hold_timed_out"   // INFO; Queue.Wait timeout branch
	EventHoldQueueFull  = "hold_queue_full"  // WARN; holdAndWait on ErrFull
	EventHoldSignaled   = "hold_signaled"    // INFO; #43 — hold elapsed signal_after_seconds; consumer got 471 + hold-id; queue continues to track resolution

	// Decision persistence (#49). Fired by the daemon's queue-level
	// DecisionPersist callback after a manual approve/deny. Both
	// in-process TUI and attach-mode control-plane decisions
	// converge through this hook.
	EventAllowlistAdded     = "allowlist_added"      // INFO; manual approve persisted to lists.allow
	EventDenylistAdded      = "denylist_added"       // INFO; manual deny persisted to lists.deny
	EventListPersistFailure = "list_persist_failure" // WARN; configwrite returned an error

	// EventAdvisorListMutationRefused fires when the decision-persist
	// callback rejects a write request whose source is the LLM
	// advisor (closes #193). Alignment principle §1: the operator's
	// allow/deny lists are human-only; an LLM-sourced verdict must
	// never reach this callback. The fix in queue.go ResolveByAdvisor
	// makes the call impossible from the inside; this event fires only
	// if a future regression re-wires the path. WARN level so the
	// rejection is visible to operators / alerts.
	EventAdvisorListMutationRefused = "advisor_list_mutation_refused" // WARN

	// Advisor lifecycle events. The *_fail constants formalize the
	// string literals introduced by issue #25.
	EventAdvisorConsulted    = "advisor_consulted"     // INFO
	EventAdvisorClassified   = "advisor_classified"    // INFO
	EventAdvisorWireFail     = "advisor_wire_fail"     // WARN; #25
	EventAdvisorSchemaFail   = "advisor_schema_fail"   // WARN; #25
	EventAdvisorUnknownFail  = "advisor_unknown_fail"  // WARN; #25
	EventAdvisorWireResponse = "advisor_wire_response" // DEBUG; HTTPClassifier per call

	// EventDiscoveryFetch fires at INFO when an agent fetches the
	// protocol discovery document at /discovery on the magic host.
	// Operator-meaningful because it indicates an agent is actively
	// reading trollbridge's wire contract — typically post-deny
	// bootstrap. Closes #95.
	EventDiscoveryFetch = "discovery_fetch" // INFO; #95

	// Suggestion-mode lifecycle (closes #168). The seven phases
	// mirror the ask-case completeness rule from #25/#33/#34/#35 —
	// every phase emits an INFO-level structured entry from day one,
	// because partial coverage is the known recurrent failure shape
	// for multi-phase flows.
	EventSuggestionDetectorRan     = "suggestion_detector_ran"     // INFO when opportunity exists, DEBUG when quiet predicate false
	EventSuggestionAskStarted      = "suggestion_ask_started"      // INFO
	EventSuggestionClassified      = "suggestion_classified"       // INFO
	EventSuggestionAskFailed       = "suggestion_ask_failed"       // WARN; kind=wire|schema|unknown
	EventSuggestionOffered         = "suggestion_offered"          // INFO
	EventSuggestionAccepted        = "suggestion_accepted"         // INFO
	EventSuggestionDeclined        = "suggestion_declined"         // INFO; per-cycle final decline (decline-row written)
	EventSuggestionDeclineFiltered = "decline_filter_suppressed"   // INFO; a candidate matched an existing decline row
	EventSuggestionSuperseded      = "suggestion_superseded"       // INFO; lists changed under the active suggestion

	// Pattern-recognition lifecycle (#203). EventPatternMatchEval
	// fires at INFO when a built-in URL pattern (azure_arm,
	// azure_keyvault, …) recognized an inbound request — this is
	// the equivalent of fastpath_eval/engine_eval for pattern
	// recognition, deliberately at INFO so an operator running
	// without --verbose sees the activity (per the ask-case
	// telemetry completeness rule). EventPatternRegistered fires
	// once per startup, listing the registered patterns.
	// EventPatternMatchPanic fires at WARN if a Pattern.Match
	// implementation panics — built-in patterns are panic-free by
	// audit, so the event firing always indicates a bug.
	EventPatternRegistered   = "patterns_registered"  // INFO; daemon startup
	EventPatternMatchEval    = "pattern_match_eval"   // INFO; per request when matched
	EventPatternMatchPanic   = "pattern_match_panic"  // WARN; defense in depth

	// EventRuleAdded fires when a pattern-shaped suggestion accept
	// appends a rule to the configured rule file (#203 follow-up).
	// Sibling of EventAllowlistAdded / EventDenylistAdded for the
	// rule-mutation channel.
	EventRuleAdded = "rule_added" // INFO; pattern suggestion accept
)

// Phase-name constants for the operational log's `phase=` field on
// per-request DEBUG records.
const (
	PhaseReceived     = "received"
	PhaseFastpathEval = "fastpath_eval"
	PhaseEngineEval   = "engine_eval"
	PhaseAdvisorCall  = "advisor_call"
	PhaseHeld         = "held"
	PhaseResolved     = "resolved"
	PhaseForwarded    = "forwarded"
	PhaseResponse     = "response"
	PhaseError        = "error"
	PhaseUpstreamDial = "upstream_dial"
	PhaseSelfDescribe = "self_describe"
)
