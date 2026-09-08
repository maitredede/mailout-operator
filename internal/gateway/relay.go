// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// Message is one submission being relayed. The body lives in a spool, which
// keeps it on the heap while it is small and moves it to a file when it is not
// — so the pod's memory is sized by configuration rather than by what a client
// chooses to send.
type Message struct {
	From string
	To   []string
	Body *spool
	// Account is the authenticated sender.
	Account string
}

// relayer delivers messages to the upstream SMTP server. Delivery is
// synchronous: the gateway only answers 250 to its client once the upstream
// has accepted the message.
//
// There is no queue, so the pod stays stateless and no message can be lost by a
// restart — retrying is the client's job. A large body does get written to disk
// for the length of its transaction (see spool), which is a buffer and not a
// queue: nothing is stored and forwarded, and the file cannot outlive the
// transaction, let alone the process.
type relayer struct {
	upstream Upstream
	// heloName is announced to the upstream.
	heloName string
	tlsCfg   *tls.Config
	log      *slog.Logger
}

func newRelayer(cfg *Config, log *slog.Logger) (*relayer, error) {
	tlsCfg := &tls.Config{
		ServerName:         cfg.Upstream.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.Upstream.InsecureSkipVerify, //nolint:gosec // opt-in, for self-signed test upstreams
	}
	if pem := cfg.Upstream.RootCAPEM; pem != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			return nil, fmt.Errorf("upstream.rootCAPEM: no certificate found")
		}
		tlsCfg.RootCAs = pool
	}
	// The CRD webhook warns about this too, but a rendered configuration is not
	// the only way to reach the dataplane: the standalone file is a supported
	// entry point, and there the choice would otherwise be silent.
	if cfg.Upstream.Username != "" && cfg.Upstream.TLS == TLSModeNone {
		log.Warn("upstream credentials will be sent in clear: upstream.tls is none",
			"host", cfg.Upstream.Host)
	}
	if cfg.Upstream.InsecureSkipVerify {
		log.Warn("upstream certificate verification is disabled",
			"host", cfg.Upstream.Host)
	}
	return &relayer{upstream: cfg.Upstream, heloName: cfg.Hostname, tlsCfg: tlsCfg, log: log}, nil
}

// send delivers one message. The error is an *smtp.SMTPError whenever the
// upstream produced one, so that its status code can be handed back to the
// submitting client unchanged: a 4xx upstream stays a 4xx for the client, and
// the client retries rather than losing the mail.
func (r *relayer) send(ctx context.Context, msg *Message) error {
	timeout := r.upstream.Timeout.D()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := r.dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Hello(r.heloName); err != nil {
		return r.wrapUpstream("EHLO", err)
	}
	if r.upstream.Username != "" {
		if err := client.Auth(sasl.NewPlainClient("", r.upstream.Username, r.upstream.Password)); err != nil {
			return r.wrapUpstream("AUTH", err)
		}
	}
	if err := client.Mail(msg.From, nil); err != nil {
		return r.wrapUpstream("MAIL FROM", err)
	}
	for _, rcpt := range msg.To {
		if err := client.Rcpt(rcpt, nil); err != nil {
			return r.wrapUpstream("RCPT TO", err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return r.wrapUpstream("DATA", err)
	}
	body, err := msg.Body.Reader()
	if err != nil {
		w.Close()
		return err
	}
	// Streamed, not written in one go: on a spooled body this is the difference
	// between a constant-size copy buffer and a second full copy on the heap.
	if _, err := io.Copy(w, body); err != nil {
		w.Close()
		return r.wrapUpstream("DATA write", err)
	}
	if err := w.Close(); err != nil {
		return r.wrapUpstream("DATA close", err)
	}
	if err := client.Quit(); err != nil {
		// The message was accepted; a failed QUIT is not worth a bounce.
		return nil
	}
	return nil
}

func (r *relayer) dial(ctx context.Context) (*smtp.Client, error) {
	addr := r.upstream.Address()
	dialer := &net.Dialer{}

	switch r.upstream.TLS {
	case TLSModeImplicit:
		conn, err := (&tls.Dialer{NetDialer: dialer, Config: r.tlsCfg}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, r.upstreamUnavailable(err)
		}
		return smtp.NewClient(conn), nil
	case TLSModeSTARTTLS:
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, r.upstreamUnavailable(err)
		}
		applyDeadline(ctx, conn)
		client, err := smtp.NewClientStartTLS(conn, r.tlsCfg)
		if err != nil {
			conn.Close()
			return nil, r.wrapUpstream("STARTTLS", err)
		}
		return client, nil
	default:
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, r.upstreamUnavailable(err)
		}
		applyDeadline(ctx, conn)
		return smtp.NewClient(conn), nil
	}
}

func applyDeadline(ctx context.Context, conn net.Conn) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
}

// upstreamUnavailable turns a dial failure into a temporary SMTP error: the
// upstream may well be back before the client's next retry. go-smtp type-asserts
// the returned error to *smtp.SMTPError, so the underlying cause cannot be
// wrapped into it — it is logged here instead.
func (r *relayer) upstreamUnavailable(err error) error {
	r.log.Error("upstream dial failed", "addr", r.upstream.Address(), "err", err)
	return &smtp.SMTPError{
		Code:         421,
		EnhancedCode: smtp.EnhancedCode{4, 4, 1},
		Message:      "Upstream server unavailable",
	}
}

// wrapUpstream keeps the upstream's own status code when it produced one, and
// falls back to a temporary failure otherwise (a network error mid-transaction
// says nothing about the message itself).
func (r *relayer) wrapUpstream(stage string, err error) error {
	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) {
		r.log.Warn("upstream rejected", "stage", stage, "code", smtpErr.Code, "message", smtpErr.Message)
		return smtpErr
	}
	r.log.Error("upstream failure", "stage", stage, "err", err)
	return &smtp.SMTPError{
		Code:         451,
		EnhancedCode: smtp.EnhancedCode{4, 4, 2},
		Message:      fmt.Sprintf("Upstream failure during %s", stage),
	}
}
