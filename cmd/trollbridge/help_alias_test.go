package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// TestRewriteHelpAlias pins the args-seam transform that maps the
// DOS-style "-?" help shorthand to cobra's canonical "-h". Tokens
// after a "--" sentinel are left alone — pflag stops parsing flags
// there and a literal "-?" in operand position belongs to the caller.
func TestRewriteHelpAlias(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"empty", nil, []string{}},
		{"no question", []string{"run", "-c", "x.yaml"}, []string{"run", "-c", "x.yaml"}},
		{"bare question", []string{"-?"}, []string{"-h"}},
		{"question after subcommand", []string{"run", "-?"}, []string{"run", "-h"}},
		{"question among other flags", []string{"-?", "--log-level", "debug"}, []string{"-h", "--log-level", "debug"}},
		{"multiple questions", []string{"-?", "sub", "-?"}, []string{"-h", "sub", "-h"}},
		{"after sentinel preserved", []string{"test", "--", "-?"}, []string{"test", "--", "-?"}},
		{"sentinel only stops question rewrites", []string{"-?", "--", "-?"}, []string{"-h", "--", "-?"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rewriteHelpAlias(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("rewriteHelpAlias(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRoot_HelpFlagAliases pins the #51 contract: the DOS-style "-?"
// produces the same help output as cobra's "-h" and "--help". Mirrors
// TestRoot_VersionFlagAliasesSubcommand. The args slice is rewritten
// in main() before Execute, so the cobra layer only ever sees "-h".
func TestRoot_HelpFlagAliases(t *testing.T) {
	render := func(t *testing.T, args []string) string {
		t.Helper()
		cmd := newRootCmd()
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(rewriteHelpAlias(args))
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute %v: %v\nstderr=%q", args, err, errOut.String())
		}
		return out.String()
	}

	canonical := render(t, []string{"--help"})
	if !strings.Contains(canonical, "Usage:") {
		t.Fatalf("--help output did not contain Usage block; got %q", canonical)
	}

	for _, args := range [][]string{
		{"-h"},
		{"-?"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if got := render(t, args); got != canonical {
				t.Errorf("output mismatch for %v\n got: %q\nwant: %q", args, got, canonical)
			}
		})
	}
}
