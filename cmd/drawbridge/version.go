package main

import (
	"fmt"

	"github.com/dandriscoll/drawbridge/internal/server"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build info.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "drawbridge", server.Version)
			return nil
		},
	}
}
