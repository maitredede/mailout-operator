// Copyright (c) 2026 Damien Daly. All rights reserved.

package source

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/maitredede/mailout-operator/internal/gateway"
	"sigs.k8s.io/yaml"
)

// File reads the configuration from a YAML file and reloads it when anything it
// depends on changes. It watches parent directories rather than files, because
// that is the only thing that works for a Kubernetes projected volume, where an
// update replaces a symlink instead of writing in place.
//
// The directories watched are the config file's own plus those of every file it
// references — certificates and DKIM keys. That is what makes a cert-manager
// renewal land in a running gateway without the operator touching the pod.
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

// referencedDirs returns every directory that must be watched for a given
// configuration: the config file's own, plus those holding the certificates and
// DKIM keys it points at.
func (f *File) referencedDirs(cfg *gateway.Config) []string {
	dirs := map[string]bool{filepath.Dir(f.path): true}
	if cfg != nil {
		for _, cert := range cfg.TLS.Certificates {
			for _, path := range []string{cert.CertFile, cert.KeyFile} {
				if path != "" {
					dirs[filepath.Dir(path)] = true
				}
			}
		}
		for _, key := range cfg.DKIM {
			if key.PrivateKeyFile != "" {
				dirs[filepath.Dir(key.PrivateKeyFile)] = true
			}
		}
	}
	out := make([]string, 0, len(dirs))
	for dir := range dirs {
		out = append(out, dir)
	}
	sort.Strings(out)
	return out
}

// Watch reloads on every change to the configuration or to the files it
// references.
func (f *File) Watch(ctx context.Context, onChange func(*gateway.Config)) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}
	defer watcher.Close()

	// The set of directories depends on the configuration itself, so it is
	// recomputed after every successful reload.
	watched := map[string]bool{}
	syncWatches := func(cfg *gateway.Config) {
		for _, dir := range f.referencedDirs(cfg) {
			if watched[dir] {
				continue
			}
			if err := watcher.Add(dir); err != nil {
				f.log.Warn("cannot watch directory", "dir", dir, "err", err)
				continue
			}
			watched[dir] = true
			f.log.Debug("watching directory", "dir", dir)
		}
	}
	// Watch what the current configuration needs; a config that fails to load
	// still leaves the config file's own directory watched.
	current, err := f.Load(ctx)
	if err != nil {
		f.log.Warn("initial watch setup: config unreadable", "err", err)
	}
	syncWatches(current)

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
			syncWatches(cfg)
			onChange(cfg)
		}
	}
}
