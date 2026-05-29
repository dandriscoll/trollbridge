package suggestion

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/config"
)

// TestAccept_AllowlistAddedHasSuggestionSource pins the #172/#174
// follow-up: suggestion accept now also emits the
// `allowlist_added` oplog event (with `source=suggestion`), so an
// operator grep'ing the standard list-mutation event class sees
// suggestion-accepted patterns alongside manual operator entries.
// Before, suggestion-driven mutations only appeared in
// `suggestion_accepted` — auditing list mutations required
// querying two event classes.
func TestAccept_AllowlistAddedHasSuggestionSource(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/v1/users",
		"POST https://api.example.com/v1/users",
	}}
	writer := &fakeWriter{}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cfgGetter := func() *config.Config { return cfg }
	m := New("/tmp/test-trollbridge.yaml", cfgGetter, &stubQueue{}, lists, stubAdvisor{}, writer, func() {}, logger)
	now := time.Unix(1_000_000_000, 0)
	m.now = func() time.Time { return now }
	m.inbound.store(now.Add(-time.Hour))

	m.Tick(context.Background())
	active := m.Active()
	if active == nil {
		t.Fatalf("expected active suggestion (lists=%+v)", lists.allow)
	}
	if err := m.Accept(context.Background(), active.ID); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "event=allowlist_added") {
		t.Errorf("expected allowlist_added event in oplog after suggestion accept; got:\n%s", out)
	}
	// Source must be `suggestion` on the new list-mutation line —
	// distinguishing it from manual operator approvals which carry
	// source=tui or source=attach.
	if !strings.Contains(out, "source=suggestion") {
		t.Errorf("expected source=suggestion on the allowlist_added line; got:\n%s", out)
	}
}
