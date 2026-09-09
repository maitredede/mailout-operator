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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/netutil"
	"golang.org/x/sync/semaphore"
)

// snapshot is everything the dataplane derives from one Config. It is built
// once and replaced wholesale, so a session always works against a consistent
// view even while a reload happens.
type snapshot struct {
	config *Config
	// newSpool builds the buffer for one message. It is derived from the
	// configuration, so a reload can change the threshold or the directory
	// without touching a transaction already in flight.
	newSpool func() *spool
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

	// Probed on every reload rather than discovered on the first large message:
	// the
	// gateway's root filesystem is read-only, so a missing or unwritable spool
	// directory is a real failure mode, and a configuration that cannot buffer
	// a message must not be accepted as valid.
	if err := probeSpool(cfg.Limits.SpoolDir); err != nil {
		return nil, err
	}

	snap := &snapshot{
		config:   cfg,
		newSpool: newSpoolFactory(cfg.Limits),
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

	// verifying bounds how many password verifications run at once.
	//
	// bcrypt at cost 12 is ~180ms of CPU by design, and AUTH is
	// pre-authentication with no cost to the client: without this, a handful of
	// connections looping AUTH with a wrong password consume every core the pod
	// has, and the relay stops answering for every tenant. It belongs to the
	// process rather than to a configuration snapshot, so a reload cannot widen
	// it. One core is left for everything else.
	verifying *semaphore.Weighted

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
	s := &Server{log: log, verifying: semaphore.NewWeighted(int64(max(1, runtime.GOMAXPROCS(0)-1)))}
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

// MetricsToken is the bearer token the metrics endpoint currently requires, or
// empty if it requires none. Read through the snapshot so that rotating it is a
// reload rather than a restart.
func (s *Server) MetricsToken() string {
	snap := s.snapshot()
	if snap == nil {
		return ""
	}
	return snap.config.Metrics.Token
}

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
		// Nothing else bounds how many messages are in flight: go-smtp has no
		// connection limit, so without this the pod's memory and CPU are sized
		// by whoever connects. Accepted connections beyond the limit wait for a
		// slot rather than being refused, which is the behaviour a mail client
		// handles best.
		l = netutil.LimitListener(l, snap.config.Limits.MaxConnections)
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
	// Applied during DATA as well as to commands, so the default of 2000 makes
	// any long body line an undeliverable message.
	srv.MaxLineLength = snap.config.Limits.MaxLineLength
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

	// authFailures counts refusals on this connection. go-smtp does not treat a
	// refused AUTH as a protocol error, so its own error threshold never fires
	// and a single connection can ask forever.
	authFailures int
}

// authVerifyTimeout bounds how long a connection waits for a verification slot.
const authVerifyTimeout = 10 * time.Second

// maxAuthFailures is how many password verifications one connection may cost
// before it stops being served. Reconnecting resets it, but that costs the
// attacker a TCP and TLS handshake for every three attempts instead of none.
const maxAuthFailures = 3

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
	if s.authFailures >= maxAuthFailures {
		// Refused without verifying anything: past this point the connection
		// has shown what it is, and every further attempt would be free CPU for
		// it and none for anyone else.
		s.server.log.Warn("too many authentication failures, closing",
			"remote", s.remoteAddr(), "attempts", s.authFailures)
		_ = s.conn.Close()
		return errTooManyAuthFailures()
	}

	// The semaphore, not the counter, is what bounds the damage: the counter is
	// per connection and an attacker simply opens more, while this holds
	// whatever the number of connections. The wait is bounded so that a flood
	// answers 451 to honest clients instead of pinning their sessions — no
	// request context reaches this callback, hence Background.
	ctx, cancel := context.WithTimeout(context.Background(), authVerifyTimeout)
	defer cancel()
	if err := s.server.verifying.Acquire(ctx, 1); err != nil {
		s.server.log.Warn("password verification saturated, deferring",
			"remote", s.remoteAddr(), "timeout", authVerifyTimeout)
		return errAuthBusy()
	}
	acct, err := s.snap.accounts.authenticate(username, password)
	s.server.verifying.Release(1)
	if err != nil {
		s.authFailures++
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
	if err := s.stillAuthorized(); err != nil {
		return err
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

// stillAuthorized re-checks the account against the configuration in service,
// and updates the session's view of it.
//
// A session captures a snapshot when it connects, which is what keeps one
// transaction consistent while a reload happens. But it also meant a credential
// stayed valid for the life of the connection: deleting the MailoutAccount, or
// setting disabled, or rotating the password changed nothing for a session
// already open — and nothing closes an idle one, since a NOOP every 50 seconds
// keeps it under the read deadline forever. A leaked credential could therefore
// keep sending after being revoked, indefinitely.
//
// Re-resolved at the start of each transaction rather than mid-message, so a
// revocation takes effect at the next envelope instead of truncating a delivery
// in flight.
func (s *session) stillAuthorized() error {
	current := s.server.snapshot()
	acct, ok := current.accounts.byUsername[s.account.Username]
	if !ok || acct.Disabled {
		s.server.log.Warn("account revoked mid-session, closing",
			"account", s.account.Username, "remote", s.remoteAddr())
		_ = s.conn.Close()
		return errCredentialsRevoked()
	}
	// The snapshot is adopted too, so the rest of the transaction sees the
	// configuration in service rather than the one from connection time: an
	// account whose senders were narrowed is held to the narrower policy.
	s.snap = current
	s.account = acct
	return nil
}

// errCredentialsRevoked closes the channel. 421 is what tells a client the
// service is going away, which is what happens to it.
func errCredentialsRevoked() *smtp.SMTPError {
	return &smtp.SMTPError{
		Code:         421,
		EnhancedCode: smtp.EnhancedCode{4, 7, 0},
		Message:      "Credentials are no longer valid",
	}
}

// errSpoolFailed is temporary: the relay could not buffer the message, which is
// its own failure and not the client's. Refusing with a 4xx keeps the message
// alive at the sender rather than losing it.
func errSpoolFailed(err error) *smtp.SMTPError {
	return &smtp.SMTPError{
		Code:         451,
		EnhancedCode: smtp.EnhancedCode{4, 3, 0},
		Message:      "Unable to buffer the message, try again later",
	}
}

// errTooManyAuthFailures ends the conversation. 421 is the code that tells a
// client the service is closing the channel, which is exactly what happens.
func errTooManyAuthFailures() *smtp.SMTPError {
	return &smtp.SMTPError{
		Code:         421,
		EnhancedCode: smtp.EnhancedCode{4, 7, 0},
		Message:      "Too many authentication failures",
	}
}

// errAuthBusy is temporary: the relay could not verify the password in time
// because it is already verifying as many as it can. A well-behaved client
// retries, and the mail is not lost.
func errAuthBusy() *smtp.SMTPError {
	return &smtp.SMTPError{
		Code:         451,
		EnhancedCode: smtp.EnhancedCode{4, 3, 2},
		Message:      "Too busy to verify credentials, try again later",
	}
}

// errMalformedHeaders is a permanent refusal. The message cannot be checked
// against the account's sender policy, and relaying something whose visible
// sender cannot be determined is exactly what the policy exists to prevent.
func errMalformedHeaders(why string) *smtp.SMTPError {
	return &smtp.SMTPError{
		Code:         550,
		EnhancedCode: smtp.EnhancedCode{5, 6, 0},
		Message:      "Malformed message headers: " + why,
	}
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
	if err := s.stillAuthorized(); err != nil {
		return err
	}
	// Counted before the message is even read: refusing an account that is over
	// quota must not first cost the relay the bandwidth and memory of the body
	// it is about to throw away.
	if err := s.snap.limiter.check(context.Background(), s.account.Username, len(s.to)); err != nil {
		s.server.metrics.messageHandled(s.account.Username, ResultDeferred)
		return err
	}

	// The Received header goes in first and the body is streamed after it, so
	// the message is written once instead of being read whole and then copied
	// to prepend a few hundred bytes.
	body := s.snap.newSpool()
	defer func() { _ = body.Close() }()
	if _, err := body.Write(s.receivedHeader()); err != nil {
		return errSpoolFailed(err)
	}
	if _, err := io.Copy(body, r); err != nil {
		return err
	}
	if body.spooled() {
		s.server.metrics.messageSpooled(s.account.Username)
	}

	msg := &Message{
		From:    s.from,
		To:      append([]string(nil), s.to...),
		Body:    body,
		Account: s.account.Username,
	}

	policy := s.snap.policyFor(s.account.Username)

	// The From header is what the recipient sees, so it is checked too: an
	// envelope that passes while the header is forged still shows a forged
	// sender, whether or not DMARC alignment catches it downstream.
	// Always checked now: an account with nothing granted may send nothing, so
	// there is no case left where the From header does not matter.
	if !policy.skipHeaderFromCheck {
		if err := checkHeaderFrom(msg.Body, policy.senders); err != nil {
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
	err := s.snap.relay.send(context.Background(), msg)
	s.server.metrics.upstreamDelivered(time.Since(start))
	if err != nil {
		s.server.log.Warn("relay failed",
			"account", msg.Account, "from", msg.From, "rcpt", len(msg.To), "err", err)
		s.server.metrics.messageHandled(msg.Account, relayResult(err))
		return err
	}
	s.server.log.Info("relayed",
		"account", msg.Account, "from", msg.From, "rcpt", len(msg.To),
		"bytes", msg.Body.Len(), "took", time.Since(start))
	s.server.metrics.messageRelayed(msg.Account, int(msg.Body.Len()))
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
// checkHeaderFrom enforces the sender policy on the From header the recipient
// will actually see.
//
// It refuses rather than skips whenever it cannot answer the question. Four ways
// around this check were found by an adversarial review, and every one of them
// worked by making the check find nothing to look at:
//
//   - a second From header, because the loop returned after the first one. The
//     signer then covered both, so the message went out with a signature that
//     verifies and a second From the MUA may be the one to display.
//   - "From :" with a space before the colon, which parsed as a header named
//     "From " and matched nothing.
//   - a first line with no colon at all, which makes the whole message body and
//     leaves no headers to check.
//   - an unparsable header block, which returned nil outright.
//
// So: exactly one well-formed From, or the message does not go. RFC 5322 §3.6
// already requires exactly one, which is what makes this strictness safe.
func checkHeaderFrom(body *spool, policy *senderPolicy) error {
	header, terminated, err := body.headerBlock()
	if err != nil {
		return errSpoolFailed(err)
	}
	if !terminated {
		// No blank line within maxHeaderBytes: this is not a message whose
		// headers can be reasoned about, and treating it as "no From found" is
		// how the check gets skipped by a megabyte of junk.
		return errMalformedHeaders("no end of header block found")
	}
	parsed, err := parseMessage(header)
	if err != nil {
		return errMalformedHeaders("unparsable header block")
	}

	var found []string
	for _, field := range parsed.Headers {
		// A header name may not carry whitespace before its colon (RFC 5322
		// §2.2), so "From " is not a From header — and must not be treated as
		// some other header either.
		if field.Name != strings.TrimRight(field.Name, " \t") {
			return errMalformedHeaders("whitespace before a header's colon")
		}
		if strings.EqualFold(field.Name, "From") {
			found = append(found, field.Value)
		}
	}
	switch len(found) {
	case 1:
		if !policy.allows(found[0]) {
			return errSenderNotAllowed(strings.TrimSpace(found[0]))
		}
		return nil
	case 0:
		return errMalformedHeaders("no From header")
	default:
		// The attack, not a formatting quirk: one From the policy allows and a
		// second one it would refuse.
		return errMalformedHeaders("more than one From header")
	}
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

// receivedHeader documents the hop, as any relay is expected to. It is written
// ahead of the body rather than prepended to it.
//
// Every interpolated value is scrubbed of anything that could end a header or
// the header block. A username that could is already refused by validUsername,
// so this is belt and braces rather than the fix — but a header sink one
// refactor away from an unchecked source is not a place to rely on a caller.
// The EHLO name, in particular, is chosen freely by whoever connects.
func (s *session) receivedHeader() []byte {
	return []byte(fmt.Sprintf("Received: from %s (%s)\r\n\tby %s (mailout) with ESMTPSA id %s;\r\n\t%s\r\n",
		headerSafe(s.conn.Hostname()), headerSafe(s.remoteAddr()), headerSafe(s.snap.config.Hostname),
		headerSafe(s.account.Username), time.Now().Format(time.RFC1123Z)))
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
