package suggestion

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// atomicTime stores a time.Time as a unix-nano int64 atomically.
// Used by Manager.inbound for the hot-path NoteInbound write so
// every request handler can call it lock-free.
type atomicTime struct {
	nano atomic.Int64
}

func (a *atomicTime) store(t time.Time) { a.nano.Store(t.UnixNano()) }
func (a *atomicTime) load() time.Time {
	n := a.nano.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

func sortStrings(s []string)   { sort.Strings(s) }
func joinNUL(s []string) string { return strings.Join(s, "\x00") }

func newSuggestionID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "sug_" + hex.EncodeToString(b[:])
}
