// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

// Package gateway implements the mailout SMTP dataplane. It deliberately has no
// dependency on the Kubernetes API: configuration is handed to it as an
// immutable snapshot, which makes the whole SMTP path testable — and runnable —
// without a cluster.
package gateway

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLSMode is how TLS is negotiated on a connection.
type TLSMode string

const (
	// TLSModeSTARTTLS negotiates TLS in-band, after the initial plaintext
	// greeting (submission, port 587).
	TLSModeSTARTTLS TLSMode = "starttls"
	// TLSModeImplicit wraps the connection in TLS from the first byte
	// (submissions, port 465).
	TLSModeImplicit TLSMode = "implicit"
	// TLSModeNone disables TLS entirely. Only ever acceptable for an upstream
	// reachable over a trusted network.
	TLSModeNone TLSMode = "none"
)

// Config is a complete, self-consistent snapshot of what the dataplane serves.
// It is replaced atomically; it is never mutated in place.
type Config struct {
	// Hostname is announced in the SMTP banner and used as the EHLO name when
	// relaying upstream.
	Hostname  string     `json:"hostname"`
	Listeners []Listener `json:"listeners"`
	TLS       TLSConfig  `json:"tls"`
	Upstream  Upstream   `json:"upstream"`
	Accounts  []Account  `json:"accounts"`
	// Milters are applied in order, each seeing the previous one's changes.
	Milters []Milter `json:"milters,omitempty"`
	// DKIM keys, one per signing domain. Signing happens after the milters.
	DKIM   []DKIMKey `json:"dkim,omitempty"`
	Limits Limits    `json:"limits"`
}

// Listener is one socket the gateway accepts submissions on.
type Listener struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
	// Mode is starttls or implicit. A listener is never plaintext: clients
	// authenticate on it, and go-smtp only offers AUTH once TLS is up.
	Mode TLSMode `json:"mode"`
}

// TLSConfig holds the certificates served to clients. Several certificates make
// the gateway answer on several names through SNI.
type TLSConfig struct {
	Certificates []CertificateRef `json:"certificates"`
	// DefaultCertificate is the certificate served when a client sends no SNI.
	// Empty means the first certificate of the list.
	DefaultCertificate string `json:"defaultCertificate,omitempty"`
}

// CertificateRef is a PEM keypair on disk, or inlined.
type CertificateRef struct {
	Name     string `json:"name,omitempty"`
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
	CertPEM  string `json:"certPEM,omitempty"`
	KeyPEM   string `json:"keyPEM,omitempty"`
}

// Upstream is the SMTP server every accepted message is relayed to.
type Upstream struct {
	Host string  `json:"host"`
	Port int     `json:"port"`
	TLS  TLSMode `json:"tls"`
	// InsecureSkipVerify disables upstream certificate verification. Intended
	// for self-signed test setups only.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
	// RootCAPEM, when set, is the only CA trusted for the upstream.
	RootCAPEM string   `json:"rootCAPEM,omitempty"`
	Username  string   `json:"username,omitempty"`
	Password  string   `json:"password,omitempty"`
	Timeout   Duration `json:"timeout,omitempty"`
}

// Address returns the dial address of the upstream.
func (u Upstream) Address() string {
	return net.JoinHostPort(u.Host, fmt.Sprint(u.Port))
}

// Account is one set of credentials an application authenticates with.
type Account struct {
	Username string `json:"username"`
	// PasswordHash is a bcrypt hash. The cleartext password never reaches the
	// dataplane.
	PasswordHash string `json:"passwordHash"`
	Disabled     bool   `json:"disabled,omitempty"`
	// DKIM, when set, replaces the gateway's signing keys for this account.
	// +optional
	DKIM []DKIMKey `json:"dkim,omitempty"`
	// DisableMilters names gateway filters to skip for this account, by name.
	// Filters can only be switched off, never added: an account must not be
	// able to route its mail through a filter of its own choosing.
	// +optional
	DisableMilters []string `json:"disableMilters,omitempty"`
}

// Limits bounds what a session may do. Zero values fall back to defaults.
type Limits struct {
	MaxMessageBytes int64    `json:"maxMessageBytes,omitempty"`
	MaxRecipients   int      `json:"maxRecipients,omitempty"`
	ReadTimeout     Duration `json:"readTimeout,omitempty"`
	WriteTimeout    Duration `json:"writeTimeout,omitempty"`
}

// Default limits, applied by Config.applyDefaults.
const (
	defaultMaxMessageBytes = 25 * 1024 * 1024
	defaultMaxRecipients   = 50
	defaultReadTimeout     = 60 * time.Second
	defaultWriteTimeout    = 60 * time.Second
	defaultUpstreamTimeout = 60 * time.Second
)

// Duration is a time.Duration that marshals as a Go duration string ("30s"),
// so that it survives the YAML-to-JSON round trip sigs.k8s.io/yaml performs.
type Duration time.Duration

// D returns the underlying time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalJSON accepts both "30s" and a plain number of nanoseconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("duration %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration: expected a string like \"30s\" or a number of nanoseconds")
	}
	*d = Duration(n)
	return nil
}

// MarshalJSON renders the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// applyDefaults fills in the zero values that have a sensible fallback.
func (c *Config) applyDefaults() {
	if c.Hostname == "" {
		c.Hostname = "mailout"
	}
	if c.Limits.MaxMessageBytes == 0 {
		c.Limits.MaxMessageBytes = defaultMaxMessageBytes
	}
	if c.Limits.MaxRecipients == 0 {
		c.Limits.MaxRecipients = defaultMaxRecipients
	}
	if c.Limits.ReadTimeout == 0 {
		c.Limits.ReadTimeout = Duration(defaultReadTimeout)
	}
	if c.Limits.WriteTimeout == 0 {
		c.Limits.WriteTimeout = Duration(defaultWriteTimeout)
	}
	if c.Upstream.Timeout == 0 {
		c.Upstream.Timeout = Duration(defaultUpstreamTimeout)
	}
	if c.Upstream.Port == 0 {
		switch c.Upstream.TLS {
		case TLSModeImplicit:
			c.Upstream.Port = 465
		default:
			c.Upstream.Port = 587
		}
	}
	for i := range c.Listeners {
		if c.Listeners[i].Mode == "" {
			c.Listeners[i].Mode = TLSModeSTARTTLS
		}
		if c.Listeners[i].Name == "" {
			c.Listeners[i].Name = c.Listeners[i].Addr
		}
	}
}

// Validate reports every problem that would make the snapshot unservable.
// Accounts are checked too: a single malformed account must not be able to take
// the whole gateway down, so callers may prefer Config.dropInvalidAccounts.
func (c *Config) Validate() error {
	var errs []string
	if len(c.Listeners) == 0 {
		errs = append(errs, "no listener configured")
	}
	seenListener := map[string]bool{}
	for i, l := range c.Listeners {
		if l.Addr == "" {
			errs = append(errs, fmt.Sprintf("listener[%d]: addr is required", i))
		}
		switch l.Mode {
		case TLSModeSTARTTLS, TLSModeImplicit:
		default:
			errs = append(errs, fmt.Sprintf("listener %q: mode must be %q or %q, got %q",
				l.Name, TLSModeSTARTTLS, TLSModeImplicit, l.Mode))
		}
		// Port 0 asks the kernel for a free port, so it is never a duplicate.
		if !strings.HasSuffix(l.Addr, ":0") {
			if seenListener[l.Addr] {
				errs = append(errs, fmt.Sprintf("listener %q: duplicate address %s", l.Name, l.Addr))
			}
			seenListener[l.Addr] = true
		}
	}
	if len(c.TLS.Certificates) == 0 {
		errs = append(errs, "tls: at least one certificate is required")
	}
	for i, cert := range c.TLS.Certificates {
		hasFiles := cert.CertFile != "" && cert.KeyFile != ""
		hasInline := cert.CertPEM != "" && cert.KeyPEM != ""
		if !hasFiles && !hasInline {
			errs = append(errs, fmt.Sprintf("tls.certificates[%d]: needs certFile+keyFile or certPEM+keyPEM", i))
		}
	}
	if c.Upstream.Host == "" {
		errs = append(errs, "upstream.host is required")
	}
	switch c.Upstream.TLS {
	case TLSModeSTARTTLS, TLSModeImplicit, TLSModeNone:
	default:
		errs = append(errs, fmt.Sprintf("upstream.tls must be one of %q, %q, %q; got %q",
			TLSModeSTARTTLS, TLSModeImplicit, TLSModeNone, c.Upstream.TLS))
	}
	seenAccount := map[string]bool{}
	for i, a := range c.Accounts {
		if a.Username == "" {
			errs = append(errs, fmt.Sprintf("accounts[%d]: username is required", i))
			continue
		}
		if seenAccount[a.Username] {
			errs = append(errs, fmt.Sprintf("accounts[%d]: duplicate username %q", i, a.Username))
		}
		seenAccount[a.Username] = true
		if a.PasswordHash == "" {
			errs = append(errs, fmt.Sprintf("account %q: passwordHash is required", a.Username))
		}
	}
	for i, m := range c.Milters {
		if _, _, err := m.ParseAddress(); err != nil {
			errs = append(errs, fmt.Sprintf("milters[%d] (%s): %v", i, m.Name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid gateway configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}
