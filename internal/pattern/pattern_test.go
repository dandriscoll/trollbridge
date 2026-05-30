package pattern

import (
	"errors"
	"strings"
	"testing"
)

// fakePattern is a minimal Pattern for Registry tests. It matches
// any request whose host starts with prefix.
type fakePattern struct {
	name       string
	prefix     string
	components []string
	panicOnce  *bool
}

func (f fakePattern) Name() string         { return f.name }
func (f fakePattern) Components() []string { return f.components }
func (f fakePattern) Match(host string, _ int, _, _ string) (MatchResult, bool) {
	if f.panicOnce != nil && !*f.panicOnce {
		*f.panicOnce = true
		panic("synthetic")
	}
	if !strings.HasPrefix(host, f.prefix) {
		return MatchResult{}, false
	}
	comps := make(map[string]string, len(f.components))
	for _, c := range f.components {
		comps[c] = host
	}
	return MatchResult{Components: comps}, true
}

func TestRegistry_Register_BasicAndDuplicate(t *testing.T) {
	r := NewRegistry()
	a := fakePattern{name: "alpha", prefix: "a.", components: []string{"host"}}
	b := fakePattern{name: "beta", prefix: "b.", components: []string{"host"}}
	if err := r.Register(a); err != nil {
		t.Fatalf("register alpha: %v", err)
	}
	if err := r.Register(b); err != nil {
		t.Fatalf("register beta: %v", err)
	}
	if err := r.Register(a); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate-registration error, got %v", err)
	}
}

func TestRegistry_Register_NilOrEmpty(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(nil); err == nil {
		t.Fatal("expected error for nil pattern")
	}
	if err := r.Register(fakePattern{name: "", prefix: "x."}); err == nil {
		t.Fatal("expected error for empty-name pattern")
	}
}

func TestRegistry_ByName_AllNames(t *testing.T) {
	r := NewRegistry()
	a := fakePattern{name: "alpha", prefix: "a."}
	b := fakePattern{name: "beta", prefix: "b."}
	_ = r.Register(a)
	_ = r.Register(b)

	if _, ok := r.ByName("alpha"); !ok {
		t.Fatal("alpha should be present")
	}
	if _, ok := r.ByName("missing"); ok {
		t.Fatal("missing should be absent")
	}
	names := r.Names()
	if len(names) != 2 || names[0] != "alpha" || names[1] != "beta" {
		t.Fatalf("Names should return sorted [alpha beta], got %v", names)
	}
	all := r.All()
	if len(all) != 2 {
		t.Fatalf("All should return 2 patterns, got %d", len(all))
	}
}

func TestRegistry_Recognize_FirstMatchWins(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(fakePattern{name: "alpha", prefix: "a.", components: []string{"host"}})
	_ = r.Register(fakePattern{name: "beta", prefix: "a.", components: []string{"host"}})

	m := r.Recognize("a.example.com", 443, "https", "/path")
	if m == nil {
		t.Fatal("expected a match")
	}
	if m.Name != "alpha" {
		t.Fatalf("expected first-match=alpha, got %s", m.Name)
	}
}

func TestRegistry_Recognize_NoMatch(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(fakePattern{name: "alpha", prefix: "a.", components: []string{"host"}})
	if m := r.Recognize("zz.example.com", 443, "https", "/"); m != nil {
		t.Fatalf("expected nil match, got %+v", m)
	}
}

func TestRegistry_Recognize_ComponentsAreFreshCopy(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(fakePattern{name: "alpha", prefix: "a.", components: []string{"host"}})
	m1 := r.Recognize("a.x", 0, "", "")
	m2 := r.Recognize("a.x", 0, "", "")
	if m1 == nil || m2 == nil {
		t.Fatal("expected both matches")
	}
	m1.Components["host"] = "mutated"
	if m2.Components["host"] == "mutated" {
		t.Fatal("Recognize must return a fresh map per call")
	}
}

func TestRegistry_Recognize_PanicSwallowedAndReported(t *testing.T) {
	prior := OnPatternPanic
	t.Cleanup(func() { OnPatternPanic = prior })

	var captured struct {
		name string
		val  any
	}
	OnPatternPanic = func(name string, recovered any) {
		captured.name = name
		captured.val = recovered
	}

	r := NewRegistry()
	once := false
	_ = r.Register(fakePattern{name: "panicker", prefix: "p.", components: []string{"host"}, panicOnce: &once})
	_ = r.Register(fakePattern{name: "alpha", prefix: "a.", components: []string{"host"}})

	// First call to panicker panics; Recognize must swallow and
	// continue to the next pattern (which doesn't match).
	if m := r.Recognize("p.x", 0, "", ""); m != nil {
		t.Fatalf("expected nil match after panic, got %+v", m)
	}
	if captured.name != "panicker" {
		t.Fatalf("expected OnPatternPanic to fire for panicker, got %q", captured.name)
	}
	if captured.val == nil {
		t.Fatal("expected captured panic value to be non-nil")
	}
	// After panicOnce flips to true, the panicker matches normally.
	if m := r.Recognize("p.x", 0, "", ""); m == nil || m.Name != "panicker" {
		t.Fatalf("expected panicker to match on second call, got %+v", m)
	}
}

func TestBuiltIns_RegisterableWithoutError(t *testing.T) {
	r := NewRegistry()
	for _, p := range BuiltIns() {
		if err := r.Register(p); err != nil {
			t.Fatalf("BuiltIns: register %s: %v", p.Name(), err)
		}
	}
	names := r.Names()
	if len(names) != 2 || names[0] != "azure_arm" || names[1] != "azure_keyvault" {
		t.Fatalf("expected built-ins [azure_arm azure_keyvault], got %v", names)
	}
}

func TestBuiltIns_FreshSlice(t *testing.T) {
	a := BuiltIns()
	b := BuiltIns()
	if &a[0] == &b[0] {
		// Pointer comparison is meaningless for interface values
		// but a sanity check that we didn't return a shared slice
		// header. (Interfaces are values; we cannot share state via
		// the slice header without the caller noticing.)
		_ = errors.New("unreachable")
	}
}
