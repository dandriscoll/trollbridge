package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/dandriscoll/drawbridge/internal/audit"
	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/spf13/cobra"
)

func newLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Inspect the audit log.",
	}
	cmd.AddCommand(newLogsTailCmd())
	return cmd
}

func newLogsTailCmd() *cobra.Command {
	var configPath string
	var follow bool
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Print the audit log in a compact human-readable form.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			f, err := os.Open(cfg.Logging.AuditPath)
			if err != nil {
				return &runtimeErr{fmt.Errorf("open audit log %s: %w", cfg.Logging.AuditPath, err)}
			}
			defer f.Close()
			return tailJSONL(f, follow, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to drawbridge.yaml")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep reading as the file grows")
	return cmd
}

func tailJSONL(r io.Reader, follow bool, out io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for {
		for scanner.Scan() {
			var e audit.Entry
			if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
				fmt.Fprintln(out, "drawbridge: unparseable audit line:", scanner.Text())
				continue
			}
			path := e.Path
			if path == "" {
				path = ""
			}
			fmt.Fprintf(out, "%s  %-6s  %-12s  %s:%d%s\n",
				e.Timestamp, e.Decision, e.IdentityID, e.Host, e.Port, path)
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		if !follow {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
}
