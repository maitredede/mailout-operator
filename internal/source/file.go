// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package source

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/maitredede/mailout-operator/internal/gateway"
	"sigs.k8s.io/yaml"
)

// File reads the configuration from a YAML file and reloads it when the file
// changes. It watches the parent directory rather than the file itself, because
// that is the only thing that works for a Kubernetes projected volume, where an
// update replaces a symlink instead of writing in place.
type File struct {
	path string
	log  *slog.Logger
	// debounce coalesces the burst of events an atomic replace produces.
	debounce time.Duration
}

// NewFile returns a source reading path.
func NewFile(path string, log *slog.Logger) *File {
	if log == nil {
		log = slog.Default()
	}
	return &File{path: path, log: log, debounce: 200 * time.Millisecond}
}

// Load parses the file.
func (f *File) Load(context.Context) (*gateway.Config, error) {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.path, err)
	}
	cfg := &gateway.Config{}
	if err := yaml.UnmarshalStrict(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", f.path, err)
	}
	return cfg, nil
}

// Watch reloads on every change to the file's directory.
func (f *File) Watch(ctx context.Context, onChange func(*gateway.Config)) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}
	defer watcher.Close()

	dir := filepath.Dir(f.path)
	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("watch %s: %w", dir, err)
	}

	var timer *time.Timer
	var fire <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			f.log.Warn("config watcher error", "err", err)
		case _, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if timer != nil {
				timer.Stop()
			}
			timer = time.NewTimer(f.debounce)
			fire = timer.C
		case <-fire:
			fire = nil
			cfg, err := f.Load(ctx)
			if err != nil {
				// A partially written file is normal mid-update; the next event
				// will bring the complete one.
				f.log.Warn("reload skipped", "err", err)
				continue
			}
			onChange(cfg)
		}
	}
}
