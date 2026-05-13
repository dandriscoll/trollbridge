package oplog

// Event-name constants for the operational log's `event=` field.
// Centralized so call sites cannot drift on the spelling.
const (
	EventStartup                  = "startup"
	EventShutdown                 = "shutdown"
	EventConfigLoaded             = "config_loaded"
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
	EventRequestHeld    = "request_held"     // INFO; holdAndWait after Enqueue success
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
