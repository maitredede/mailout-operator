// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/maitredede/mailout-operator/internal/gateway"
	"github.com/maitredede/mailout-operator/internal/source"
	"github.com/spf13/cobra"
)

func newGatewayCommand() *cobra.Command {
	var (
		configPath string
		logLevel   string
		logFormat  string
	)
	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Run the SMTP dataplane",
		Long: "Run the SMTP dataplane from a configuration file. This mode needs no " +
			"Kubernetes cluster, which is what makes the relay testable with " +
			"docker-compose and testcontainers.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			log, err := newLogger(logLevel, logFormat)
			if err != nil {
				return err
			}
			return runGateway(cmd.Context(), configPath, log)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "/etc/mailout/gateway.yaml", "path to the gateway configuration")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "debug, info, warn or error")
	cmd.Flags().StringVar(&logFormat, "log-format", "text", "text or json")
	return cmd
}

func runGateway(ctx context.Context, configPath string, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	src := source.NewFile(configPath, log)
	cfg, err := src.Load(ctx)
	if err != nil {
		return err
	}
	srv, err := gateway.NewServer(cfg, log)
	if err != nil {
		return err
	}

	go func() {
		// A rejected reload leaves the running configuration in place: a bad
		// update must never take the relay down.
		if err := src.Watch(ctx, func(cfg *gateway.Config) {
			if err := srv.Reload(cfg); err != nil {
				log.Error("configuration rejected, keeping the previous one", "err", err)
			}
		}); err != nil {
			log.Error("configuration watcher stopped", "err", err)
		}
	}()

	return srv.Run(ctx)
}

func newLogger(level, format string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil
	default:
		return nil, fmt.Errorf("invalid log format %q, want text or json", format)
	}
}
