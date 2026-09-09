// Copyright (c) 2026 Damien Daly. All rights reserved.

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
	DKIM []DKIMKey `json:"dkim,omitempty"`
	// RateLimit caps what each account may send, counted in a store shared by
	// every replica of the gateway. Absent means no quota at all.
	RateLimit *RateLimit    `json:"rateLimit,omitempty"`
	Limits    Limits        `json:"limits"`
	Metrics   MetricsConfig `json:"metrics,omitempty"`
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
	// AllowedSenders lists the addresses this account may send from, as an
	// exact address (app@example.com) or a whole domain (*@example.com).
	//
	// Empty means no restriction on the envelope — and no signature at all:
	// declaring a sender is what earns a DKIM signature, because signing a
	// domain vouches for it, and an account must not vouch for a domain it may
	// not send from.
	// +optional
	AllowedSenders []string `json:"allowedSenders,omitempty"`
	// SkipHeaderFromCheck stops the policy from being applied to the From
	// header, leaving it on the envelope only. Off by default, so the safe
	// behaviour is the zero value: an account that passes the envelope check
	// but forges its From header would still show a forged sender to the
	// recipient, DMARC alignment failure notwithstanding.
	// +optional
	SkipHeaderFromCheck bool `json:"skipHeaderFromCheck,omitempty"`
}

// MetricsConfig guards the Prometheus endpoint.
type MetricsConfig struct {
	// Token, when set, must be presented as `Authorization: Bearer <token>`.
	//
	// The endpoint carries no credential and no message content, but it does
	// list the accounts served, the domains signed and the volume each account
	// sends — enough to map the tenants of a shared gateway. In a cluster the
	// operator generates this and hands the same value to Prometheus; empty
	// leaves the endpoint open, which is the standalone case, and is logged as
	// a warning rather than assumed to be deliberate.
	Token string `json:"token,omitempty"`
}

// Limits bounds what a session may do. Zero values fall back to defaults.
type Limits struct {
	MaxMessageBytes int64    `json:"maxMessageBytes,omitempty"`
	MaxRecipients   int      `json:"maxRecipients,omitempty"`
	ReadTimeout     Duration `json:"readTimeout,omitempty"`
	WriteTimeout    Duration `json:"writeTimeout,omitempty"`

	// MaxLineLength caps one line of a command or of message data.
	//
	// go-smtp defaults to 2000 and applies it during DATA too, so any body line
	// longer than that makes the message undeliverable — and plenty of real
	// senders emit long lines: unwrapped HTML, a long References header. RFC
	// 5321 §4.5.3.1.6 only requires 1000 to be accepted, so this is a ceiling
	// rather than a promise.
	MaxLineLength int `json:"maxLineLength,omitempty"`

	// MaxConnections caps concurrent connections per listener.
	//
	// Without it nothing bounds how many messages are in flight, so the pod's
	// memory is sized by whoever connects rather than by configuration — and
	// go-smtp offers no limit of its own.
	MaxConnections int `json:"maxConnections,omitempty"`

	// SpoolDir is where a message too large to keep on the heap is written for
	// the length of its transaction. Empty means the system temporary
	// directory. The file is unlinked as soon as it is created, so nothing
	// survives the transaction, let alone the process.
	SpoolDir string `json:"spoolDir,omitempty"`

	// SpoolThreshold is the size past which a message body moves from memory to
	// that directory. Below it, staying on the heap is both simpler and faster;
	// above it, the point is that a 25 MiB message must not cost 25 MiB of heap
	// per connection.
	SpoolThreshold int64 `json:"spoolThreshold,omitempty"`
}

// Default limits, applied by Config.applyDefaults.
const (
	defaultMaxMessageBytes = 25 * 1024 * 1024
	defaultMaxRecipients   = 50
	// A pod is sized for a number of connections, not for a number of clients.
	// 64 in flight at 25 MiB each is what sizes the spool volume; on the heap it
	// would be 1.6 GiB, which is exactly what the spool exists to prevent.
	defaultMaxConnections = 64
	// Generous next to the 2000 go-smtp defaults to, because the failure mode
	// is a message thrown away rather than anything saved.
	defaultMaxLineLength   = 8000
	defaultSpoolThreshold  = 1024 * 1024
	defaultReadTimeout     = 60 * time.Second
	defaultWriteTimeout    = 60 * time.Second
	defaultUpstreamTimeout = 60 * time.Second
)

// RejectedAccount is an account left out of the served configuration, with the
// reason to report.
type RejectedAccount struct {
	Username string
	Reason   string
}

// PartitionAccounts splits the accounts into those that can be served and those
// that cannot. Being permissive about the set while being strict about each
// member is what keeps one tenant's mistake to itself.
func (c *Config) PartitionAccounts() (served []Account, rejected []RejectedAccount) {
	seen := map[string]bool{}
	for i, account := range c.Accounts {
		switch {
		case account.Username == "":
			rejected = append(rejected, RejectedAccount{
				Username: fmt.Sprintf("accounts[%d]", i),
				Reason:   "username is required",
			})
		case seen[account.Username]:
			rejected = append(rejected, RejectedAccount{
				Username: account.Username,
				Reason:   "duplicate username",
			})
		case !ValidUsername(account.Username):
			rejected = append(rejected, RejectedAccount{
				// The username is not echoed back: it is precisely the value
				// that may carry control characters, and this reason travels to
				// a Kubernetes status and to the logs.
				Username: fmt.Sprintf("accounts[%d]", i),
				Reason: fmt.Sprintf("username must be at most %d printable ASCII characters "+
					"without space or delimiter", MaxUsernameLength),
			})
		case account.PasswordHash == "":
			rejected = append(rejected, RejectedAccount{
				Username: account.Username,
				Reason:   "passwordHash is required",
			})
		case !UsableHash(account.PasswordHash):
			rejected = append(rejected, RejectedAccount{
				Username: account.Username,
				Reason: fmt.Sprintf("passwordHash must be a bcrypt hash of cost %d to %d; "+
					"a malformed hash answers instantly and a costly one stalls the relay",
					MinBcryptCost, MaxBcryptCost),
			})
		default:
			seen[account.Username] = true
			served = append(served, account)
		}
	}
	return served, rejected
}

// maxUsernameLength bounds what the operator's CRD already bounds, for the
// configurations that never went through it — the standalone file is a
// supported entry point.
const MaxUsernameLength = 128

// validUsername reports whether a username is safe to serve.
//
// This is the load-bearing check, not a nicety: the username is interpolated
// into the Received header of every message the account sends, so a CR or LF in
// it ends the header block and hands the account control of the headers and the
// body that follow. It is also a component of every rate limiting key. Refusing
// the account is the only answer that holds for both.
func ValidUsername(username string) bool {
	if username == "" || len(username) > MaxUsernameLength {
		return false
	}
	for _, b := range []byte(username) {
		// Printable ASCII only, and not the delimiters that would let one
		// username be read as another somewhere downstream.
		if b <= ' ' || b > '~' || b == ':' || b == ';' || b == ',' || b == '"' || b == '\\' {
			return false
		}
	}
	return true
}

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
	if c.Limits.MaxConnections == 0 {
		c.Limits.MaxConnections = defaultMaxConnections
	}
	if c.Limits.MaxLineLength == 0 {
		c.Limits.MaxLineLength = defaultMaxLineLength
	}
	if c.Limits.SpoolThreshold == 0 {
		c.Limits.SpoolThreshold = defaultSpoolThreshold
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

// Validate reports every problem that would make the snapshot unservable —
// listeners, certificates, upstream, filters: what is common to every account.
//
// Accounts are deliberately NOT validated here. They are checked one by one by
// PartitionAccounts, because a single malformed account must never stop the
// relay for all the others: on a shared gateway that would let one tenant deny
// service to the rest.
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
	if c.RateLimit != nil && len(c.RateLimit.Store.Addresses) == 0 {
		// The relay fails closed on a store it cannot reach, so publishing a
		// quota with nowhere to count would stop mail rather than cap it.
		errs = append(errs, "rateLimit.store.addresses is required")
	}
	if c.RateLimit != nil && c.RateLimit.Store.InsecureSkipVerify && !c.RateLimit.Store.TLS {
		// The TLS configuration is only built when tls is on, so this field
		// was silently ignored — and someone who wrote it believed the
		// connection was encrypted, when it was carrying the store's password
		// in clear.
		errs = append(errs, "rateLimit.store.insecureSkipVerify requires tls: true; "+
			"without TLS the connection carries the store password in clear")
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
