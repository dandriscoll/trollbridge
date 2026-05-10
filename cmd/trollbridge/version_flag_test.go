package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/server"
)

// TestRoot_VersionFlagAliasesSubcommand pins the #44 contract: the
// `--version` long flag and its `-v` shorthand both produce the same
// output as the existing `trollbridge version` subcommand. Operators
// who type either form (CLI conventions vary across tools) must see
// identical bytes so scripts that parse the version line see one
// shape, not two.
func TestRoot_VersionFlagAliasesSubcommand(t *testing.T) {
	expected := "trollbridge " + server.Version + "\n"

	for _, args := range [][]string{
		{"--version"},
		{"-v"},
		{"version"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cmd := newRootCmd()
			var out, errOut bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute %v: %v\nstderr=%q", args, err, errOut.String())
			}
			if out.String() != expected {
				t.Errorf("output mismatch for %v\n got: %q\nwant: %q", args, out.String(), expected)
			}
		})
	}
}
