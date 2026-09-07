// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

// Package source provides the dataplane's configuration, from a file when the
// gateway runs standalone (docker-compose, tests) or from the Kubernetes API
// when it runs under the operator. The dataplane only ever sees a Config, which
// is what lets the whole SMTP path be exercised without a cluster.
package source

import (
	"context"

	"github.com/maitredede/mailout-operator/internal/gateway"
)

// Source produces gateway configurations.
type Source interface {
	// Load returns the current configuration.
	Load(ctx context.Context) (*gateway.Config, error)
	// Watch calls onChange for every subsequent configuration, and blocks until
	// ctx is done. A source with nothing to watch simply waits.
	Watch(ctx context.Context, onChange func(*gateway.Config)) error
}
