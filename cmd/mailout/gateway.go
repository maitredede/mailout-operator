// Copyright (c) 2026 Damien Daly. All rights reserved.

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
	"golang.org/x/sync/errgroup"
)

func newGatewayCommand() *cobra.Command {
	var (
		configPath  string
		metricsAddr string
		logLevel    string
		logFormat   string
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
			return runGateway(cmd.Context(), configPath, metricsAddr, log)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "/etc/mailout/gateway.yaml", "path to the gateway configuration")
	cmd.Flags().StringVar(&metricsAddr, "metrics-bind-address", ":9090",
		"address the Prometheus endpoint listens on, empty to disable it")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "debug, info, warn or error")
	cmd.Flags().StringVar(&logFormat, "log-format", "text", "text or json")
	return cmd
}

func runGateway(ctx context.Context, configPath, metricsAddr string, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	src := source.NewFile(configPath, log)
	cfg, err := src.Load(ctx)
	if err != nil {
		return err
	}
	// Once, at startup. Unlinking a body as soon as it is created makes this
	// unnecessary in every ordinary case; what is left is a container that
	// restarted inside the same pod, where the emptyDir outlives the process.
	gateway.SweepSpool(cfg.Limits.SpoolDir, log)

	metrics := gateway.NewMetrics()
	srv, err := gateway.NewServer(cfg, log, gateway.WithMetrics(metrics))
	if err != nil {
		return err
	}

	// The two share a context: a metrics endpoint that cannot bind is a
	// configuration error, and starting the relay half-instrumented would hide
	// it until someone went looking for a dashboard.
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error { return gateway.ServeMetrics(ctx, metricsAddr, metrics, srv.MetricsToken, log) })

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

	group.Go(func() error { return srv.Run(ctx) })
	return group.Wait()
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
