// Copyright (c) 2026 Damien Daly. All rights reserved.

// Command mailout is both halves of the operator: the SMTP dataplane
// ("gateway") and the Kubernetes controller manager ("operator"). One binary,
// one image, two roles.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is stamped at build time with -X main.version. The Dockerfile has
// always passed it; until this variable existed, go build silently discarded
// the flag and there was no way to ask a running pod what it was.
//
// Knowing that matters here: one image serves both roles, and the operator
// hands its own image to every gateway it deploys, so a stale tag propagates
// silently.
var version = "dev"

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the build version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	}
}

func main() {
	root := &cobra.Command{
		Use:           "mailout",
		Short:         "SMTP relay driven by Kubernetes custom resources",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.Version = version
	root.AddCommand(newGatewayCommand(), newOperatorCommand(), newHashPasswordCommand(),
		newDKIMKeyCommand(), newVersionCommand())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
