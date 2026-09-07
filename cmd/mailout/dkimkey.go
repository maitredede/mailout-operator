// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package main

import (
	"fmt"
	"os"

	"github.com/maitredede/mailout-operator/internal/gateway"
	"github.com/spf13/cobra"
)

func newDKIMKeyCommand() *cobra.Command {
	var (
		domain    string
		selector  string
		algorithm string
		outFile   string
	)
	cmd := &cobra.Command{
		Use:   "dkim-key",
		Short: "Generate a DKIM signing key and the DNS record that publishes it",
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := gateway.GenerateDKIMKey(algorithm, domain, selector)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if outFile != "" {
				if err := os.WriteFile(outFile, []byte(key.PrivateKeyPEM), 0o600); err != nil {
					return fmt.Errorf("write %s: %w", outFile, err)
				}
				fmt.Fprintf(out, "private key written to %s\n", outFile)
			} else {
				fmt.Fprint(out, key.PrivateKeyPEM)
			}
			fmt.Fprintf(out, "\nPublish this TXT record:\n%s\n  %s\n",
				key.DNSRecordName, key.DNSRecordValue)
			return nil
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "signing domain (required)")
	cmd.Flags().StringVar(&selector, "selector", "mail", "selector")
	cmd.Flags().StringVar(&algorithm, "algorithm", "rsa", "rsa or ed25519")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write the private key here instead of stdout")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}
