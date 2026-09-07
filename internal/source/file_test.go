// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package source

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maitredede/mailout-operator/internal/gateway"
)

const sampleConfig = `
hostname: mail.example.test
listeners:
  - name: submission
    addr: ":587"
    mode: starttls
tls:
  certificates:
    - name: gw
      certFile: /certs/tls.crt
      keyFile: /certs/tls.key
upstream:
  host: smtp.example.test
  port: 587
  tls: starttls
  username: relay
  password: hunter2
  timeout: 30s
accounts:
  - username: app1
    passwordHash: "$2a$12$abcdefghijklmnopqrstuv"
limits:
  maxMessageBytes: 1048576
  readTimeout: 45s
`

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestFileLoad(t *testing.T) {
	src := NewFile(writeConfig(t, sampleConfig), slog.New(slog.DiscardHandler))
	cfg, err := src.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Hostname != "mail.example.test" {
		t.Fatalf("hostname = %q", cfg.Hostname)
	}
	if len(cfg.Listeners) != 1 || cfg.Listeners[0].Mode != gateway.TLSModeSTARTTLS {
		t.Fatalf("listeners = %+v", cfg.Listeners)
	}
	if cfg.Upstream.Timeout.D() != 30*time.Second {
		t.Fatalf("upstream timeout = %v", cfg.Upstream.Timeout.D())
	}
	if cfg.Limits.ReadTimeout.D() != 45*time.Second {
		t.Fatalf("read timeout = %v", cfg.Limits.ReadTimeout.D())
	}
	if len(cfg.Accounts) != 1 || cfg.Accounts[0].Username != "app1" {
		t.Fatalf("accounts = %+v", cfg.Accounts)
	}
}

// An unknown field is a typo, and a typo in a security-relevant setting must
// not pass silently.
func TestFileLoadRejectsUnknownField(t *testing.T) {
	src := NewFile(writeConfig(t, sampleConfig+"\nnosuchfield: true\n"), slog.New(slog.DiscardHandler))
	if _, err := src.Load(t.Context()); err == nil {
		t.Fatal("expected an error for an unknown field")
	}
}

func TestFileWatchReloads(t *testing.T) {
	path := writeConfig(t, sampleConfig)
	src := NewFile(path, slog.New(slog.DiscardHandler))
	src.debounce = 10 * time.Millisecond

	changes := make(chan *gateway.Config, 4)
	go func() {
		_ = src.Watch(t.Context(), func(cfg *gateway.Config) { changes <- cfg })
	}()
	// Give the watcher time to register before touching the file.
	time.Sleep(100 * time.Millisecond)

	updated := strings.Replace(sampleConfig,
		"accounts:\n  - username: app1",
		"accounts:\n  - username: app2\n    passwordHash: \"$2a$12$zzzzzzzzzzzzzzzzzzzzzz\"\n  - username: app1", 1)
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}

	select {
	case cfg := <-changes:
		if len(cfg.Accounts) != 2 {
			t.Fatalf("reloaded config has %d accounts, want 2", len(cfg.Accounts))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reload observed")
	}
}
