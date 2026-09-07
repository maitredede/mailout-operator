// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// snapshot is everything the dataplane derives from one Config. It is built
// once and replaced wholesale, so a session always works against a consistent
// view even while a reload happens.
type snapshot struct {
	config   *Config
	accounts *accountStore
	certs    *certStore
	relay    *relayer
}

func newSnapshot(cfg *Config, log *slog.Logger) (*snapshot, error) {
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
	return &snapshot{
		config:   cfg,
		accounts: newAccountStore(cfg.Accounts),
		certs:    certs,
		relay:    relay,
	}, nil
}

// Server is the SMTP dataplane. Its configuration can be replaced at runtime
// with Reload; the listening sockets, however, are fixed for the lifetime of
// the process (changing them is a Deployment change, which restarts the pod).
type Server struct {
	log     *slog.Logger
	current atomic.Pointer[snapshot]

	mu      sync.Mutex
	servers []*smtp.Server

	// onListen, when set, is called with the resolved address of each listener
	// once it is open. Tests use it to discover kernel-assigned ports.
	onListen func(l Listener, addr string)
}

// NewServer builds a dataplane serving cfg.
func NewServer(cfg *Config, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{log: log}
	if err := s.Reload(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload swaps in a new configuration. An invalid configuration is rejected and
// the previous one stays in service: a bad update must never take the relay
// down.
func (s *Server) Reload(cfg *Config) error {
	snap, err := newSnapshot(cfg, s.log)
	if err != nil {
		return err
	}
	s.current.Store(snap)
	s.log.Info("configuration loaded",
		"accounts", len(snap.config.Accounts),
		"certificates", len(snap.config.TLS.Certificates),
		"upstream", snap.config.Upstream.Address())
	return nil
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
		if s.onListen != nil {
			s.onListen(lc, l.Addr().String())
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
	s.from = from
	s.to = nil
	return nil
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

	// Deliberately not tied to the server's lifetime: a delivery in flight
	// should finish rather than be cancelled by a shutdown. The relayer applies
	// its own timeout, which is what bounds this call.
	start := time.Now()
	if err := s.snap.relay.send(context.Background(), msg); err != nil {
		s.server.log.Warn("relay failed",
			"account", msg.Account, "from", msg.From, "rcpt", len(msg.To), "err", err)
		return err
	}
	s.server.log.Info("relayed",
		"account", msg.Account, "from", msg.From, "rcpt", len(msg.To),
		"bytes", len(msg.Data), "took", time.Since(start))
	return nil
}

// prependReceived documents the hop, as any relay is expected to.
func (s *session) prependReceived(data []byte) []byte {
	header := fmt.Sprintf("Received: from %s (%s)\r\n\tby %s (mailout) with ESMTPSA id %s;\r\n\t%s\r\n",
		s.conn.Hostname(), s.remoteAddr(), s.snap.config.Hostname,
		s.account.Username, time.Now().Format(time.RFC1123Z))
	return append([]byte(header), data...)
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
