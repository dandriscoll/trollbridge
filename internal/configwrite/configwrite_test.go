package configwrite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = `# drawbridge example
drawbridge_version: 2

# Adapter — top-level head comment.
adapter: lo

ports:
  proxy: 8080
  control: 8081

# Lists are inline; drawbridge writes them back.
lists:
  allow:
    - existing.example
  deny:
    - 169.254.169.254

# LLM section keeps its head comment after a write.
llm:
  enabled: false
`

func writeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "drawbridge.yaml")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestAddAllow_InsertsSorted(t *testing.T) {
	path := writeFixture(t)
	changed, err := AddAllow(path, "new.example")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("changed = false, want true")
	}
	got := read(t, path)
	for _, want := range []string{"existing.example", "new.example"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q after AddAllow:\n%s", want, got)
		}
	}
	// Sort: 'existing' < 'new' alphabetically.
	if strings.Index(got, "new.example") < strings.Index(got, "existing.example") {
		t.Errorf("entries not sorted ascending:\n%s", got)
	}
}

func TestAddAllow_Idempotent(t *testing.T) {
	path := writeFixture(t)
	first, err := AddAllow(path, "existing.example")
	if err != nil {
		t.Fatal(err)
	}
	if first {
		t.Errorf("first add of duplicate: changed = true, want false")
	}
}

func TestAddDeny_PreservesAllowList(t *testing.T) {
	path := writeFixture(t)
	if _, err := AddDeny(path, "pastebin.com"); err != nil {
		t.Fatal(err)
	}
	got := read(t, path)
	if !strings.Contains(got, "existing.example") {
		t.Errorf("deny add removed allow entry:\n%s", got)
	}
	if !strings.Contains(got, "pastebin.com") {
		t.Errorf("deny entry not added:\n%s", got)
	}
}

func TestRemoveAllow_DropsEntry(t *testing.T) {
	path := writeFixture(t)
	changed, err := RemoveAllow(path, "existing.example")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("changed = false on existing entry")
	}
	got := read(t, path)
	if strings.Contains(got, "existing.example") {
		t.Errorf("entry not removed:\n%s", got)
	}
}

func TestPreservesHeadCommentsOutsideListsSubtree(t *testing.T) {
	path := writeFixture(t)
	if _, err := AddAllow(path, "z.example"); err != nil {
		t.Fatal(err)
	}
	got := read(t, path)
	for _, want := range []string{
		"# drawbridge example",
		"# Adapter — top-level head comment.",
		"# LLM section keeps its head comment after a write.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("comment %q lost after write:\n%s", want, got)
		}
	}
}

func TestAtomicWrite_DoesNotLeaveTempFile(t *testing.T) {
	path := writeFixture(t)
	if _, err := AddAllow(path, "z.example"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".drawbridge-yaml-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}
