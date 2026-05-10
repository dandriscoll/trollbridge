package main

import (
	"fmt"
	"os"
)

func main() {
	cmd := newRootCmd()
	cmd.SetArgs(rewriteHelpAlias(os.Args[1:]))
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCodeFor(err))
	}
}

// rewriteHelpAlias rewrites the legacy/DOS help shorthand "-?" to
// cobra's canonical "-h" so that `trollbridge -?` (and the same on any
// subcommand) prints help instead of cobra's "unknown shorthand flag"
// error. pflag only allows one shorthand per flag, so the rewrite
// happens at the args seam rather than via flag registration. Tokens
// after the "--" sentinel are left untouched: pflag stops parsing
// flags there, and a literal "-?" in operand position belongs to the
// caller.
func rewriteHelpAlias(args []string) []string {
	out := make([]string, len(args))
	rewrite := true
	for i, a := range args {
		if rewrite && a == "--" {
			rewrite = false
		}
		if rewrite && a == "-?" {
			out[i] = "-h"
			continue
		}
		out[i] = a
	}
	return out
}
