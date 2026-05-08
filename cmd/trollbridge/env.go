package main

import (
	"fmt"

	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/envprint"
	"github.com/spf13/cobra"
)

func newEnvCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Print shell `export` lines that route HTTP clients through this trollbridge.",
		Long: `Print shell exports for HTTPS_PROXY, HTTP_PROXY, and NO_PROXY (both
upper- and lowercase), derived from the proxy's listen address in
trollbridge.yaml. Designed for:

    eval "$(trollbridge env -c ~/.trollbridge/trollbridge.yaml)"

The proxy URL pins to 127.0.0.1 when listen.address is the wildcard
0.0.0.0 (clients dial a real address, not the bind wildcard).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			fmt.Fprint(cmd.OutOrStdout(), envprint.Render(cfg))
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml")
	return cmd
}
