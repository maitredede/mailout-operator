// Copyright (c) 2026 Damien Daly. All rights reserved.

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/maitredede/mailout-operator/internal/gateway"
	"github.com/spf13/cobra"
)

func newHashPasswordCommand() *cobra.Command {
	var generate bool
	cmd := &cobra.Command{
		Use:   "hash-password [password]",
		Short: "Print the bcrypt hash a gateway configuration expects",
		Long: "Hash a password for a standalone gateway configuration. With no argument " +
			"the password is read from stdin; with --generate a random one is created " +
			"and both halves are printed.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var password string
			switch {
			case generate:
				var err error
				if password, err = gateway.GeneratePassword(); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "password: %s\n", password)
			case len(args) == 1:
				// Visible in /proc/<pid>/cmdline to anything running as the
				// same user, and in the shell's history afterwards. Kept
				// because it is convenient and sometimes it is a throwaway
				// password, but not silently.
				fmt.Fprintln(cmd.ErrOrStderr(),
					"warning: a password on the command line is visible in /proc and in your shell "+
						"history. Pipe it on stdin instead: echo -n 'secret' | mailout hash-password")
				password = args[0]
			default:
				line, err := bufio.NewReader(os.Stdin).ReadString('\n')
				if err != nil && line == "" {
					return fmt.Errorf("read password from stdin: %w", err)
				}
				password = strings.TrimRight(line, "\r\n")
			}
			hash, err := gateway.HashPassword(password)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "passwordHash: %s\n", hash)
			return nil
		},
	}
	cmd.Flags().BoolVar(&generate, "generate", false, "generate a random password instead of reading one")
	return cmd
}
