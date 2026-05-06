package console

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runWith drives the REPL with a canned input string and returns
// the captured stdout.
func runWith(t *testing.T, allowPath, denyPath, input string) string {
	t.Helper()
	in := strings.NewReader(input)
	var out bytes.Buffer
	cfg := Config{
		AllowPaths: []string{allowPath},
		DenyPaths:  []string{denyPath},
		In:         in,
		Out:        &out,
		Prompt:     "> ",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Run(ctx, cfg); err != nil && err != io.EOF {
		t.Fatalf("Run: %v", err)
	}
	return out.String()
}

func setupFiles(t *testing.T, allowSeed, denySeed string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	a := filepath.Join(dir, "allow.txt")
	d := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(a, []byte(allowSeed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d, []byte(denySeed), 0o600); err != nil {
		t.Fatal(err)
	}
	return a, d
}

func TestConsole_AllowAddsToFile(t *testing.T) {
	a, d := setupFiles(t, "existing.example\n", "")
	out := runWith(t, a, d, "allow new.example\nquit\n")
	if !strings.Contains(out, "added new.example") {
		t.Errorf("expected confirmation; got: %s", out)
	}
	body, _ := os.ReadFile(a)
	if !strings.Contains(string(body), "new.example") {
		t.Errorf("file did not receive entry:\n%s", string(body))
	}
}

func TestConsole_AllowRejectsBadPattern(t *testing.T) {
	a, d := setupFiles(t, "", "")
	out := runWith(t, a, d, "allow api.*.foo\nquit\n")
	if !strings.Contains(out, "invalid pattern") {
		t.Errorf("expected invalid-pattern error; got: %s", out)
	}
	body, _ := os.ReadFile(a)
	if strings.TrimSpace(string(body)) != "" {
		t.Errorf("file should not have been written: %s", string(body))
	}
}

func TestConsole_AllowResultIsSorted(t *testing.T) {
	a, d := setupFiles(t, "z.example.com\na.example.com\n", "")
	runWith(t, a, d, "allow m.example.com\nquit\n")
	body, _ := os.ReadFile(a)
	got := strings.TrimSpace(string(body))
	want := "a.example.com\nm.example.com\nz.example.com"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestConsole_DenyAddsToFile(t *testing.T) {
	a, d := setupFiles(t, "", "")
	out := runWith(t, a, d, "deny pastebin.com\nquit\n")
	if !strings.Contains(out, "added pastebin.com") {
		t.Errorf("expected deny confirmation; got: %s", out)
	}
	body, _ := os.ReadFile(d)
	if !strings.Contains(string(body), "pastebin.com") {
		t.Errorf("deny file did not receive entry: %s", string(body))
	}
}

func TestConsole_RemoveDropsLineFromAllOcurrences(t *testing.T) {
	a, d := setupFiles(t, "a.example\nb.example\n", "a.example\n")
	out := runWith(t, a, d, "remove a.example\nquit\n")
	if !strings.Contains(out, "removed a.example") {
		t.Errorf("expected remove confirmation; got: %s", out)
	}
	aBody, _ := os.ReadFile(a)
	dBody, _ := os.ReadFile(d)
	if strings.Contains(string(aBody), "a.example") {
		t.Errorf("a.example still in allow.txt: %s", string(aBody))
	}
	if strings.Contains(string(dBody), "a.example") {
		t.Errorf("a.example still in deny.txt: %s", string(dBody))
	}
}

func TestConsole_ListPrintsCurrentEntries(t *testing.T) {
	a, d := setupFiles(t, "x.example\n", "y.example\n")
	out := runWith(t, a, d, "list all\nquit\n")
	if !strings.Contains(out, "x.example") || !strings.Contains(out, "y.example") {
		t.Errorf("list missing entries: %s", out)
	}
}

func TestConsole_HelpIsAvailable(t *testing.T) {
	a, d := setupFiles(t, "", "")
	out := runWith(t, a, d, "help\nquit\n")
	for _, k := range []string{"allow", "deny", "remove", "list", "help"} {
		if !strings.Contains(out, k) {
			t.Errorf("help missing %q: %s", k, out)
		}
	}
}

func TestConsole_UnknownCommandPrintsError(t *testing.T) {
	a, d := setupFiles(t, "", "")
	out := runWith(t, a, d, "frob\nquit\n")
	if !strings.Contains(out, "unknown command") {
		t.Errorf("expected unknown-command message; got: %s", out)
	}
}

func TestConsole_QuitExitsCleanly(t *testing.T) {
	a, d := setupFiles(t, "", "")
	in := strings.NewReader("quit\n")
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Run(ctx, Config{AllowPaths: []string{a}, DenyPaths: []string{d}, In: in, Out: &out}); err != nil {
		t.Fatal(err)
	}
}
