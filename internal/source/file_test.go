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

// A cert-manager renewal rewrites the certificate Secret, not the config file.
// The watcher must notice, or a renewed certificate would never reach a running
// gateway.
func TestFileWatchNoticesReferencedFileChange(t *testing.T) {
	certDir := t.TempDir()
	certFile := filepath.Join(certDir, "tls.crt")
	keyFile := filepath.Join(certDir, "tls.key")
	for _, path := range []string{certFile, keyFile} {
		if err := os.WriteFile(path, []byte("placeholder"), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	config := strings.Replace(sampleConfig,
		"      certFile: /certs/tls.crt\n      keyFile: /certs/tls.key",
		"      certFile: "+certFile+"\n      keyFile: "+keyFile, 1)
	src := NewFile(writeConfig(t, config), slog.New(slog.DiscardHandler))
	src.debounce = 10 * time.Millisecond

	changes := make(chan *gateway.Config, 4)
	go func() {
		_ = src.Watch(t.Context(), func(cfg *gateway.Config) { changes <- cfg })
	}()
	time.Sleep(100 * time.Millisecond)

	if err := os.WriteFile(certFile, []byte("renewed"), 0o600); err != nil {
		t.Fatalf("rewrite certificate: %v", err)
	}
	select {
	case <-changes:
	case <-time.After(5 * time.Second):
		t.Fatal("a change to the certificate file did not trigger a reload")
	}
}

func TestReferencedDirs(t *testing.T) {
	src := NewFile("/etc/mailout/gateway.yaml", slog.New(slog.DiscardHandler))
	dirs := src.referencedDirs(&gateway.Config{
		TLS: gateway.TLSConfig{Certificates: []gateway.CertificateRef{
			{CertFile: "/etc/mailout/tls/a/tls.crt", KeyFile: "/etc/mailout/tls/a/tls.key"},
			{CertPEM: "inline", KeyPEM: "inline"},
		}},
		DKIM: []gateway.DKIMKey{
			{PrivateKeyFile: "/etc/mailout/dkim/example/private.key"},
			{PrivateKeyPEM: "inline"},
		},
	})
	want := []string{"/etc/mailout", "/etc/mailout/dkim/example", "/etc/mailout/tls/a"}
	if len(dirs) != len(want) {
		t.Fatalf("got %v, want %v", dirs, want)
	}
	for i := range want {
		if dirs[i] != want[i] {
			t.Fatalf("got %v, want %v", dirs, want)
		}
	}
}
