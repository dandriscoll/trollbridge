package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dandriscoll/drawbridge/internal/config"
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
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to drawbridge.yaml")
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
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to drawbridge.yaml")
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
			body, err := controlGET(cfg, "/v1/sessions")
			if err != nil {
				return &runtimeErr{err}
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(body))
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to drawbridge.yaml")
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
	url := fmt.Sprintf("http://%s/v1/holds/%s/%s", cfg.Approvals.ControlListen, id, action)
	body, _ := json.Marshal(map[string]string{"scope": scope, "reason": reason})
	httpClient := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return &runtimeErr{fmt.Errorf("control API: %w", err)}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return &holdNotFoundErr{fmt.Errorf("hold %s not found", id)}
	}
	if resp.StatusCode >= 400 {
		return &runtimeErr{fmt.Errorf("control API: %s: %s", resp.Status, string(respBody))}
	}
	fmt.Fprintln(out, string(respBody))
	return nil
}

func controlGET(cfg *config.Config, path string) ([]byte, error) {
	url := fmt.Sprintf("http://%s%s", cfg.Approvals.ControlListen, path)
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s: %s", resp.Status, string(body))
	}
	return io.ReadAll(resp.Body)
}
