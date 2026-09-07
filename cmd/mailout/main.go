// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

// Command mailout is both halves of the operator: the SMTP dataplane
// ("gateway") and the Kubernetes controller manager ("operator"). One binary,
// one image, two roles.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:           "mailout",
		Short:         "SMTP relay driven by Kubernetes custom resources",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newGatewayCommand(), newHashPasswordCommand(), newDKIMKeyCommand())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
