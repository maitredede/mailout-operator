// Copyright (c) 2026 Damien Daly. All rights reserved.

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
				if err := writePrivateKey(outFile, key.PrivateKeyPEM); err != nil {
					return err
				}
				fmt.Fprintf(out, "private key written to %s (mode 0600)\n", outFile)
			} else {
				// A signing key lives for years; a terminal's scrollback, a
				// `tee`, or a CI log lives longer. Say so rather than assume
				// the caller meant it.
				fmt.Fprintln(cmd.ErrOrStderr(),
					"warning: writing the private key to stdout. Use -o to write it to a file "+
						"with restrictive permissions instead.")
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

// writePrivateKey writes the key with an explicit mode.
//
// os.WriteFile applies its mode only when it *creates* the file, so rotating a
// key into an existing path kept whatever mode was there — and this project's
// own gen-certs.sh leaves keys at 0644, so regenerating through that path left
// a world-readable signing key. Chmod after opening is what makes the mode
// true in both cases.
func writePrivateKey(path, pemData string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict %s: %w", path, err)
	}
	if _, err := f.WriteString(pemData); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
}
