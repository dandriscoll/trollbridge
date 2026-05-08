package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/controlclient"
	"github.com/spf13/cobra"
)

func newApproveCmd() *cobra.Command {
	var configPath, scope string
	cmd := &cobra.Command{
		Use:   "approve <hold-id>",
		Short: "Approve a held request via the control API.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return holdAction(configPath, args[0], "approve", scope, "", cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml")
	cmd.Flags().StringVar(&scope, "scope", "once", "approval scope (once | session | rule)")
	return cmd
}

func newDenyCmd() *cobra.Command {
	var configPath, reason string
	cmd := &cobra.Command{
		Use:   "deny <hold-id>",
		Short: "Deny a held request via the control API.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return holdAction(configPath, args[0], "deny", "", reason, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml")
	cmd.Flags().StringVar(&reason, "reason", "operator denied", "reason recorded in the audit log")
	return cmd
}

func newSessionsCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "Show active client sessions and their decision counts.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			body, err := controlclient.Get(cfg, "/v1/sessions")
			if err != nil {
				return &runtimeErr{err}
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(body))
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml")
	return cmd
}

func holdAction(configPath, id, action, scope, reason string, out io.Writer) error {
	if configPath == "" {
		configPath = defaultConfigPath()
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return &configErr{err}
	}
	respBody, err := controlclient.HoldAction(cfg, id, action, scope, reason)
	if err != nil {
		if errors.Is(err, controlclient.ErrHoldNotFound) {
			return &holdNotFoundErr{fmt.Errorf("hold %s not found", id)}
		}
		return &runtimeErr{err}
	}
	fmt.Fprintln(out, string(respBody))
	return nil
}
