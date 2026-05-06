package hostlist

import (
	"reflect"
	"strings"
	"testing"
)

func TestSmart_LiteralHostsAlphaByReversedLabels(t *testing.T) {
	in := []string{"zoo.example.com", "api.example.com", "bar.example.com"}
	got := Smart(in)
	want := []string{"api.example.com", "bar.example.com", "zoo.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSmart_GroupsByReversedDomain(t *testing.T) {
	in := []string{"api.github.com", "registry.npmjs.org", "files.pythonhosted.org", "github.com"}
	got := Smart(in)
	// Reversed-label sort: com.github*, com.npmjs.registry, ... wait
	// note that .com sorts before .org. github.com (com.github) sorts
	// before api.github.com (com.github.api) because the prefix is
	// same length up to "github" and shorter wins.
	want := []string{
		"github.com",
		"api.github.com",
		"registry.npmjs.org",
		"files.pythonhosted.org",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSmart_WildcardSortsAfterLiteralAtSameDepth(t *testing.T) {
	in := []string{"*.github.com", "api.github.com", "github.com"}
	got := Smart(in)
	want := []string{"github.com", "api.github.com", "*.github.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSmart_BareWildcardSortsLast(t *testing.T) {
	in := []string{"*", "example.com", "*.example.com"}
	got := Smart(in)
	// "example.com" (com.example), "*.example.com"
	// (com.example.*), then bare "*" (just ["*"]).
	want := []string{"example.com", "*.example.com", "*"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSmart_PortAndPathTieBreak(t *testing.T) {
	in := []string{"a.com:443", "a.com", "a.com:80", "a.com/x"}
	got := Smart(in)
	want := []string{"a.com", "a.com/x", "a.com:80", "a.com:443"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSmart_PreservesLeadingComments(t *testing.T) {
	in := []string{
		"# header",
		"# coding agent baseline",
		"",
		"zoo.example.com",
		"api.example.com",
	}
	got := Smart(in)
	if got[0] != "# header" || got[1] != "# coding agent baseline" {
		t.Errorf("leading comments not preserved: %v", got)
	}
	if got[len(got)-2] != "api.example.com" || got[len(got)-1] != "zoo.example.com" {
		t.Errorf("entries not sorted after header: %v", got)
	}
}

func TestSmart_DropsBlankLinesAmongPatterns(t *testing.T) {
	in := []string{"b.example", "", "a.example", ""}
	got := Smart(in)
	want := []string{"a.example", "b.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSmart_PreservesInlineCommentsWithPattern(t *testing.T) {
	in := []string{"b.example  # second", "a.example  # first"}
	got := Smart(in)
	if !strings.Contains(got[0], "a.example") || !strings.Contains(got[0], "first") {
		t.Errorf("inline comment lost: %v", got)
	}
}

func TestAppendUnique_AddsAndSorts(t *testing.T) {
	in := []string{"a.example.com", "z.example.com"}
	out, added := AppendUnique(in, "m.example.com")
	if !added {
		t.Fatal("expected added=true")
	}
	want := []string{"a.example.com", "m.example.com", "z.example.com"}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("got %v, want %v", out, want)
	}
}

func TestAppendUnique_DuplicateIsNoop(t *testing.T) {
	in := []string{"api.github.com"}
	_, added := AppendUnique(in, "API.GitHub.COM") // case-insensitive
	if added {
		t.Error("expected added=false for case-equivalent duplicate")
	}
}

func TestRemoveMatching_DropsMatchKeepsRest(t *testing.T) {
	in := []string{
		"# header",
		"a.example",
		"b.example",
		"a.example",
	}
	out, removed := RemoveMatching(in, "a.example")
	if !removed {
		t.Fatal("expected removed=true")
	}
	want := []string{"# header", "b.example"}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("got %v, want %v", out, want)
	}
}

func TestRemoveMatching_AbsentReturnsFalse(t *testing.T) {
	in := []string{"a.example"}
	_, removed := RemoveMatching(in, "z.example")
	if removed {
		t.Error("expected removed=false")
	}
}
