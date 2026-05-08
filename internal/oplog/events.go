package oplog

// Event-name constants for the operational log's `event=` field.
// Centralized so call sites cannot drift on the spelling.
const (
	EventStartup                  = "startup"
	EventShutdown                 = "shutdown"
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
	EventInterceptError           = "intercept_error"
	EventInterceptHandshakeFail   = "intercept_handshake_failure"
	EventAuditWriteFailure        = "audit_write_failure"
	EventAuditEncodeFailure       = "audit_encode_failure"
	EventControlPlaneError        = "control_plane_error"
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
)
