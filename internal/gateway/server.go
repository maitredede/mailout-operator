// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/redis/go-redis/v9"
)

// snapshot is everything the dataplane derives from one Config. It is built
// once and replaced wholesale, so a session always works against a consistent
// view even while a reload happens.
type snapshot struct {
	config *Config
	// rejected lists the accounts left out of this snapshot and why. They are
	// reported rather than fatal: one tenant's broken account must not stop the
	// relay for everyone.
	rejected []RejectedAccount
	accounts *accountStore
	certs    *certStore
	relay    *relayer
	milters  *milterChain
	dkim     *dkimSigner
	// limiter counts against the shared quota store. Nil when the gateway
	// declares no rateLimit.
	limiter *limiter
	// policies holds the per-account filter chain and signer. An account with
	// no override shares the gateway's own.
	policies map[string]accountPolicy
}

// accountPolicy is what applies to one account's messages.
type accountPolicy struct {
	milters *milterChain
	// senders decides which addresses the account may use, and therefore which
	// domains may be signed on its behalf.
	senders             *senderPolicy
	skipHeaderFromCheck bool
}

func newSnapshot(cfg *Config, log *slog.Logger, metrics *Metrics, prev *snapshot) (*snapshot, error) {
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	certs, err := newCertStore(cfg.TLS)
	if err != nil {
		return nil, err
	}
	relay, err := newRelayer(cfg, log)
	if err != nil {
		return nil, err
	}
	milters, err := newMilterChain(cfg, log, metrics)
	if err != nil {
		return nil, err
	}
	signer, err := newDKIMSigner(cfg.DKIM, log, metrics)
	if err != nil {
		return nil, err
	}
	// The quota store's connection pool outlives a reload that did not touch it:
	// reconnecting on every account change would drop the pool for no reason,
	// and a gateway that fails closed cannot afford a gap.
	lim := reusableLimiter(prev, cfg)
	if lim == nil {
		if lim, err = newLimiter(cfg, log, metrics); err != nil {
			return nil, err
		}
	}

	served, rejected := cfg.PartitionAccounts()
	for _, account := range rejected {
		log.Error("account not served", "account", account.Username, "reason", account.Reason)
	}

	snap := &snapshot{
		config:   cfg,
		rejected: rejected,
		accounts: newAccountStore(served),
		certs:    certs,
		relay:    relay,
		milters:  milters,
		dkim:     signer,
		limiter:  lim,
		policies: make(map[string]accountPolicy, len(served)),
	}
	for _, acct := range served {
		policy := accountPolicy{
			milters:             milters,
			senders:             newSenderPolicy(acct.AllowedSenders),
			skipHeaderFromCheck: acct.SkipHeaderFromCheck,
		}
		if len(acct.DisableMilters) > 0 {
			policy.milters = milters.without(acct.DisableMilters)
		}
		snap.policies[acct.Username] = policy
	}
	return snap, nil
}

// reusableLimiter returns the previous snapshot's limiter when the new
// configuration describes the very same store, and nil when a new one must be
// built.
func reusableLimiter(prev *snapshot, cfg *Config) *limiter {
	if prev == nil || prev.limiter == nil || cfg.RateLimit == nil {
		return nil
	}
	if !sameStore(prev.limiter.limits.Store, cfg.RateLimit.Store) {
		return nil
	}
	// The connection is the same; the limits themselves may well have changed.
	reused := *prev.limiter
	reused.limits = *cfg.RateLimit
	reused.gateway = cfg.Hostname
	return &reused
}

// policyFor returns what applies to an account. An account absent from the
// snapshot cannot authenticate in the first place, so the fallback is the
// strictest thing that still makes sense: the gateway's filters, and a policy
// that signs nothing.
func (s *snapshot) policyFor(username string) accountPolicy {
	if policy, ok := s.policies[username]; ok {
		return policy
	}
	return accountPolicy{milters: s.milters, senders: newSenderPolicy(nil)}
}

// Server is the SMTP dataplane. Its configuration can be replaced at runtime
// with Reload; the listening sockets, however, are fixed for the lifetime of
// the process (changing them is a Deployment change, which restarts the pod).
type Server struct {
	log     *slog.Logger
	metrics *Metrics
	current atomic.Pointer[snapshot]

	mu      sync.Mutex
	servers []*smtp.Server

	// onListen, when set, is called with the resolved address of each listener
	// once it is open. Tests use it to discover kernel-assigned ports.
	onListen func(l Listener, addr string)
}

// SetOnListen registers a callback invoked with each listener's resolved
// address once it is open. It exists for tests that bind port 0 and therefore
// only learn the port from the kernel.
func (s *Server) SetOnListen(fn func(l Listener, addr string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onListen = fn
}

// ServerOption tunes a Server at construction.
type ServerOption func(*Server)

// WithMetrics instruments the dataplane. Without it the server counts nothing,
// which is what the tests that do not care about metrics get.
func WithMetrics(m *Metrics) ServerOption {
	return func(s *Server) { s.metrics = m }
}

// NewServer builds a dataplane serving cfg.
func NewServer(cfg *Config, log *slog.Logger, opts ...ServerOption) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{log: log}
	for _, opt := range opts {
		opt(s)
	}
	if err := s.Reload(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload swaps in a new configuration. An invalid configuration is rejected and
// the previous one stays in service: a bad update must never take the relay
// down.
func (s *Server) Reload(cfg *Config) error {
	previous := s.current.Load()
	snap, err := newSnapshot(cfg, s.log, s.metrics, previous)
	if err != nil {
		s.metrics.configReloaded("failure", 0, 0)
		return err
	}
	s.current.Store(snap)
	// A store the new configuration no longer points at is closed. Sessions
	// still holding the old snapshot then fail closed, which is the same answer
	// they would get from a store that had genuinely gone away — and changing
	// the store under a running relay is not an everyday operation.
	if previous != nil && previous.limiter != nil && previous.limiter.client != snap.limiterClient() {
		previous.limiter.close()
	}
	// After the swap, so the gauges never describe a configuration that is not
	// the one being served.
	s.metrics.configReloaded("success", len(snap.accounts.byUsername), len(snap.rejected))
	s.log.Info("configuration loaded",
		"accounts", len(snap.accounts.byUsername),
		"accountsRejected", len(snap.rejected),
		"certificates", len(snap.config.TLS.Certificates),
		"milters", len(snap.config.Milters),
		"dkimKeys", len(snap.config.DKIM),
		"upstream", snap.config.Upstream.Address())
	return nil
}

// limiterClient is the connection the snapshot uses, or nil when it counts
// nothing.
func (s *snapshot) limiterClient() redis.UniversalClient {
	if s == nil || s.limiter == nil {
		return nil
	}
	return s.limiter.client
}

func (s *Server) snapshot() *snapshot { return s.current.Load() }

// Run opens every configured listener and serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	snap := s.snapshot()
	var listeners []net.Listener
	closeAll := func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}

	errs := make(chan error, len(snap.config.Listeners))
	var wg sync.WaitGroup
	for _, lc := range snap.config.Listeners {
		l, err := net.Listen("tcp", lc.Addr)
		if err != nil {
			closeAll()
			return fmt.Errorf("listen %s (%s): %w", lc.Addr, lc.Name, err)
		}
		listeners = append(listeners, l)
		if lc.Mode == TLSModeImplicit {
			l = tls.NewListener(l, s.tlsConfig())
		}
		srv := s.newSMTPServer(lc)
		s.mu.Lock()
		s.servers = append(s.servers, srv)
		s.mu.Unlock()

		s.log.Info("listening", "name", lc.Name, "addr", l.Addr().String(), "mode", lc.Mode)
		s.mu.Lock()
		onListen := s.onListen
		s.mu.Unlock()
		if onListen != nil {
			onListen(lc, l.Addr().String())
		}
		wg.Add(1)
		go func(lc Listener, l net.Listener) {
			defer wg.Done()
			if err := srv.Serve(l); err != nil && !errors.Is(err, net.ErrClosed) {
				errs <- fmt.Errorf("listener %s: %w", lc.Name, err)
			}
		}(lc, l)
	}

	select {
	case <-ctx.Done():
	case err := <-errs:
		s.Close()
		wg.Wait()
		return err
	}
	s.Close()
	wg.Wait()
	return nil
}

// Close shuts every listener down.
func (s *Server) Close() {
	s.mu.Lock()
	servers := s.servers
	s.servers = nil
	s.mu.Unlock()
	for _, srv := range servers {
		_ = srv.Close()
	}
	s.snapshot().limiter.close()
}

// newSMTPServer builds the go-smtp server for one listener. TLS is wired to the
// certificate store through GetCertificate, which covers both STARTTLS and
// implicit TLS, so SNI works on either port.
func (s *Server) newSMTPServer(lc Listener) *smtp.Server {
	snap := s.snapshot()
	srv := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		return &session{server: s, conn: c, snap: s.snapshot()}, nil
	}))
	srv.Domain = snap.config.Hostname
	srv.MaxMessageBytes = snap.config.Limits.MaxMessageBytes
	srv.MaxRecipients = snap.config.Limits.MaxRecipients
	srv.ReadTimeout = snap.config.Limits.ReadTimeout.D()
	srv.WriteTimeout = snap.config.Limits.WriteTimeout.D()
	srv.ErrorLog = slogAdapter{s.log}
	// Certificates are looked up on the live snapshot, so a reload takes effect
	// on the next handshake without reopening the socket. The same callback
	// serves STARTTLS and implicit TLS, which is what makes SNI work on both.
	srv.TLSConfig = s.tlsConfig()

	// AUTH is only offered over TLS (go-smtp enforces this unless
	// AllowInsecureAuth is set), which is exactly the policy we want: no
	// credential ever crosses the wire in clear.
	srv.AllowInsecureAuth = false
	return srv
}

// tlsConfig serves certificates from whichever snapshot is current at handshake
// time.
func (s *Server) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.snapshot().certs.getCertificate(hello)
		},
	}
}

// slogAdapter lets go-smtp log through slog.
type slogAdapter struct{ log *slog.Logger }

func (a slogAdapter) Printf(format string, v ...any) { a.log.Warn(fmt.Sprintf(format, v...)) }
func (a slogAdapter) Println(v ...any)               { a.log.Warn(fmt.Sprint(v...)) }

// session is one client connection. It captures the configuration snapshot at
// connection time so that a reload cannot change the rules mid-transaction.
type session struct {
	server *Server
	conn   *smtp.Conn
	snap   *snapshot

	account *Account
	from    string
	to      []string
}

var _ smtp.AuthSession = (*session)(nil)

func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

func (s *session) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(_, username, password string) error {
			return s.authenticate(username, password)
		}), nil
	case sasl.Login:
		return newLoginServer(s.authenticate), nil
	default:
		return nil, smtp.ErrAuthUnknownMechanism
	}
}

func (s *session) authenticate(username, password string) error {
	acct, err := s.snap.accounts.authenticate(username, password)
	if err != nil {
		s.server.log.Warn("authentication refused",
			"username", username, "remote", s.remoteAddr(), "reason", err)
		// Only a username the gateway actually serves becomes a label: the one
		// on the wire is chosen by the caller, and would let anyone mint time
		// series by guessing names.
		s.server.metrics.authFailed(s.snap.accounts.label(username))
		return smtp.ErrAuthFailed
	}
	s.account = acct
	s.server.log.Info("authenticated", "username", username, "remote", s.remoteAddr())
	return nil
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if s.account == nil {
		return smtp.ErrAuthRequired
	}
	policy := s.snap.policyFor(s.account.Username)
	if !policy.senders.allows(from) {
		s.server.log.Warn("envelope sender refused",
			"account", s.account.Username, "from", from, "remote", s.remoteAddr())
		s.server.metrics.messageHandled(s.account.Username, ResultRejected)
		return errSenderNotAllowed(from)
	}
	s.from = from
	s.to = nil
	return nil
}

// errSenderNotAllowed is a permanent refusal: the account is not configured for
// this sender, and retrying will not change that.
func errSenderNotAllowed(address string) *smtp.SMTPError {
	return &smtp.SMTPError{
		Code:         550,
		EnhancedCode: smtp.EnhancedCode{5, 7, 1},
		Message:      fmt.Sprintf("Sender %s is not allowed for this account", address),
	}
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.account == nil {
		return smtp.ErrAuthRequired
	}
	s.to = append(s.to, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	if s.account == nil {
		return smtp.ErrAuthRequired
	}
	if len(s.to) == 0 {
		return &smtp.SMTPError{
			Code:         554,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "No valid recipients",
		}
	}
	// Counted before the message is even read: refusing an account that is over
	// quota must not first cost the relay the bandwidth and memory of the body
	// it is about to throw away.
	if err := s.snap.limiter.check(context.Background(), s.account.Username, len(s.to)); err != nil {
		s.server.metrics.messageHandled(s.account.Username, ResultDeferred)
		return err
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	msg := &Message{
		From:    s.from,
		To:      append([]string(nil), s.to...),
		Data:    s.prependReceived(data),
		Account: s.account.Username,
	}

	policy := s.snap.policyFor(s.account.Username)

	// The From header is what the recipient sees, so it is checked too: an
	// envelope that passes while the header is forged still shows a forged
	// sender, whether or not DMARC alignment catches it downstream.
	if !policy.skipHeaderFromCheck && !policy.senders.empty() {
		if err := checkHeaderFrom(msg.Data, policy.senders); err != nil {
			s.server.log.Warn("From header refused",
				"account", s.account.Username, "envelope", msg.From, "remote", s.remoteAddr())
			s.server.metrics.messageHandled(msg.Account, ResultRejected)
			return err
		}
	}

	// Filters run before signing, so that DKIM covers the body the filters
	// actually left behind.
	if !policy.milters.empty() {
		if err := policy.milters.run(context.Background(), msg, s.sessionInfo()); err != nil {
			if errors.Is(err, errDiscard) {
				s.server.log.Info("message discarded by a filter",
					"account", msg.Account, "from", msg.From)
				s.server.metrics.messageHandled(msg.Account, ResultDiscarded)
				return nil
			}
			s.server.log.Info("message rejected by a filter",
				"account", msg.Account, "from", msg.From, "err", err)
			s.server.metrics.messageHandled(msg.Account, filterResult(err))
			return err
		}
	}

	// Signed last, so the signature covers what the filters left behind.
	if !s.snap.dkim.empty() {
		if err := s.snap.dkim.sign(msg, policy.senders); err != nil {
			s.server.log.Error("DKIM signing failed", "account", msg.Account, "err", err)
			s.server.metrics.messageHandled(msg.Account, ResultDeferred)
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "Unable to sign the message, try again later",
			}
		}
	}

	// Deliberately not tied to the server's lifetime: a delivery in flight
	// should finish rather than be cancelled by a shutdown. The relayer applies
	// its own timeout, which is what bounds this call.
	start := time.Now()
	err = s.snap.relay.send(context.Background(), msg)
	s.server.metrics.upstreamDelivered(time.Since(start))
	if err != nil {
		s.server.log.Warn("relay failed",
			"account", msg.Account, "from", msg.From, "rcpt", len(msg.To), "err", err)
		s.server.metrics.messageHandled(msg.Account, relayResult(err))
		return err
	}
	s.server.log.Info("relayed",
		"account", msg.Account, "from", msg.From, "rcpt", len(msg.To),
		"bytes", len(msg.Data), "took", time.Since(start))
	s.server.metrics.messageRelayed(msg.Account, len(msg.Data))
	return nil
}

// filterResult and relayResult classify a refusal by what the client should do
// about it, which is what the SMTP code already says: 4xx means try again, 5xx
// means never. Counting them apart is what separates "the upstream is down"
// from "this tenant is sending mail it is not allowed to send".
func filterResult(err error) string { return resultFor(err, ResultRejected) }

func relayResult(err error) string { return resultFor(err, ResultDeferred) }

func resultFor(err error, fallback string) string {
	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) {
		if smtpErr.Code >= 500 {
			return ResultRejected
		}
		return ResultDeferred
	}
	return fallback
}

// checkHeaderFrom applies the sender policy to the message's From header. A
// message with no From header is left alone: that is a malformed message, not a
// spoofing attempt, and the upstream is entitled to its own opinion on it.
func checkHeaderFrom(data []byte, policy *senderPolicy) error {
	parsed, err := parseMessage(data)
	if err != nil {
		// Unparsable here means unparsable for the upstream too; let it decide.
		return nil
	}
	for _, header := range parsed.Headers {
		if !strings.EqualFold(header.Name, "From") {
			continue
		}
		if !policy.allows(header.Value) {
			return errSenderNotAllowed(strings.TrimSpace(header.Value))
		}
		return nil
	}
	return nil
}

// sessionInfo describes the session to the milters, through the sendmail macros
// they expect.
func (s *session) sessionInfo() sessionInfo {
	info := sessionInfo{
		Hostname: s.conn.Hostname(),
		MTAName:  s.snap.config.Hostname,
	}
	if s.account != nil {
		info.AuthUser = s.account.Username
	}
	if c := s.conn.Conn(); c != nil {
		if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			info.RemoteIP = addr.IP.String()
			info.RemotePort = uint16(addr.Port)
		}
	}
	if state, ok := s.conn.TLSConnectionState(); ok {
		info.TLSVersion = tls.VersionName(state.Version)
		info.TLSCipher = tls.CipherSuiteName(state.CipherSuite)
	}
	return info
}

// prependReceived documents the hop, as any relay is expected to.
//
// Every interpolated value is scrubbed of anything that could end a header or
// the header block. A username that could is already refused by validUsername,
// so this is belt and braces rather than the fix — but a header sink one
// refactor away from an unchecked source is not a place to rely on a caller.
// The EHLO name, in particular, is chosen freely by whoever connects.
func (s *session) prependReceived(data []byte) []byte {
	header := fmt.Sprintf("Received: from %s (%s)\r\n\tby %s (mailout) with ESMTPSA id %s;\r\n\t%s\r\n",
		headerSafe(s.conn.Hostname()), headerSafe(s.remoteAddr()), headerSafe(s.snap.config.Hostname),
		headerSafe(s.account.Username), time.Now().Format(time.RFC1123Z))
	return append([]byte(header), data...)
}

// headerSafeLimit keeps one interpolated value from pushing the Received header
// past what a receiver will accept, whatever the caller passed.
const headerSafeLimit = 128

// headerSafe renders a value harmless inside a header: no CR, no LF, no NUL,
// nothing unprintable, and bounded in length.
func headerSafe(value string) string {
	if len(value) > headerSafeLimit {
		value = value[:headerSafeLimit]
	}
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return '?'
		}
		return r
	}, value)
}

func (s *session) remoteAddr() string {
	if c := s.conn.Conn(); c != nil {
		return c.RemoteAddr().String()
	}
	return "unknown"
}

func (s *session) Reset() {
	s.from = ""
	s.to = nil
}

func (s *session) Logout() error { return nil }
