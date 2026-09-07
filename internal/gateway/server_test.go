// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package gateway

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/maitredede/mailout-operator/internal/pki"
)

// receivedMessage is one message the fake upstream accepted.
type receivedMessage struct {
	From string
	To   []string
	Data []byte
}

// fakeUpstream is a plaintext SMTP server standing in for the target relay.
type fakeUpstream struct {
	addr string

	mu       sync.Mutex
	messages []receivedMessage
	// rejectWith, when set, is returned instead of accepting the message.
	rejectWith error
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	up := &fakeUpstream{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := smtp.NewServer(smtp.BackendFunc(func(*smtp.Conn) (smtp.Session, error) {
		return &fakeUpstreamSession{up: up}, nil
	}))
	srv.Domain = "upstream.test"
	srv.AllowInsecureAuth = true
	up.addr = l.Addr().String()
	go func() { _ = srv.Serve(l) }()
	// The server owns the listener; closing it from Cleanup is what stops it,
	// and Cleanup runs after t.Context() is already cancelled.
	t.Cleanup(func() { _ = srv.Close() })
	return up
}

func (u *fakeUpstream) received() []receivedMessage {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]receivedMessage(nil), u.messages...)
}

func (u *fakeUpstream) reject(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rejectWith = err
}

type fakeUpstreamSession struct {
	up   *fakeUpstream
	from string
	to   []string
}

func (s *fakeUpstreamSession) Mail(from string, _ *smtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *fakeUpstreamSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}

func (s *fakeUpstreamSession) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.up.mu.Lock()
	defer s.up.mu.Unlock()
	if s.up.rejectWith != nil {
		return s.up.rejectWith
	}
	s.up.messages = append(s.up.messages, receivedMessage{From: s.from, To: s.to, Data: data})
	return nil
}

func (s *fakeUpstreamSession) Reset()        { s.from, s.to = "", nil }
func (s *fakeUpstreamSession) Logout() error { return nil }

// testGateway is a running dataplane plus what a client needs to reach it.
type testGateway struct {
	submissionAddr string
	smtpsAddr      string
	upstream       *fakeUpstream
	caPool         *x509.CertPool
}

const (
	testAccount  = "app1"
	testPassword = "s3cret"
	testCertName = "mail.gateway.test"
)

func newTestGateway(t *testing.T, opts ...func(*Config)) *testGateway {
	t.Helper()
	upstream := newFakeUpstream(t)

	ca, err := pki.NewCA("mailout-test")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	kp, err := ca.Issue(testCertName, "localhost", "127.0.0.1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)

	upHost, upPort := splitHostPort(t, upstream.addr)
	cfg := &Config{
		Hostname: "gateway.test",
		Listeners: []Listener{
			{Name: "submission", Addr: "127.0.0.1:0", Mode: TLSModeSTARTTLS},
			{Name: "smtps", Addr: "127.0.0.1:0", Mode: TLSModeImplicit},
		},
		TLS: TLSConfig{Certificates: []CertificateRef{
			{Name: "gw", CertPEM: string(kp.CertPEM), KeyPEM: string(kp.KeyPEM)},
		}},
		Upstream: Upstream{Host: upHost, Port: upPort, TLS: TLSModeNone},
		Accounts: []Account{
			{Username: testAccount, PasswordHash: mustHash(t, testPassword)},
		},
	}

	for _, opt := range opts {
		opt(cfg)
	}

	srv, err := NewServer(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Port 0 means the kernel picks the port, so the addresses are only known
	// once the listeners are open: Run reports them back through a channel.
	addrs := make(chan string, 2)
	srv.onListen = func(_ Listener, addr string) { addrs <- addr }

	ctx := t.Context()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("gateway did not stop")
		}
	})

	gw := &testGateway{upstream: upstream, caPool: pool}
	for range 2 {
		select {
		case addr := <-addrs:
			if gw.submissionAddr == "" {
				gw.submissionAddr = addr
			} else {
				gw.smtpsAddr = addr
			}
		case <-time.After(5 * time.Second):
			t.Fatal("gateway did not start listening")
		}
	}
	return gw
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port %q: %v", port, err)
	}
	return host, n
}

func (gw *testGateway) clientTLS() *tls.Config {
	return &tls.Config{ServerName: testCertName, RootCAs: gw.caPool, MinVersion: tls.VersionTLS12}
}

// dialSubmission connects on the STARTTLS listener and upgrades.
func (gw *testGateway) dialSubmission(t *testing.T) *smtp.Client {
	t.Helper()
	c, err := smtp.DialStartTLS(gw.submissionAddr, gw.clientTLS())
	if err != nil {
		t.Fatalf("DialStartTLS: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestSubmissionRelaysMessage(t *testing.T) {
	gw := newTestGateway(t)
	c := gw.dialSubmission(t)

	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH PLAIN: %v", err)
	}
	body := "Subject: hello\r\n\r\nbody\r\n"
	if err := c.SendMail("app@example.test", []string{"dest@example.test"}, strings.NewReader(body)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	msgs := gw.upstream.received()
	if len(msgs) != 1 {
		t.Fatalf("upstream got %d messages, want 1", len(msgs))
	}
	if msgs[0].From != "app@example.test" || msgs[0].To[0] != "dest@example.test" {
		t.Fatalf("envelope = %s -> %v", msgs[0].From, msgs[0].To)
	}
	if !strings.Contains(string(msgs[0].Data), "Subject: hello") {
		t.Fatalf("body not relayed: %q", msgs[0].Data)
	}
	if !strings.HasPrefix(string(msgs[0].Data), "Received: from ") {
		t.Fatalf("no Received header prepended: %q", msgs[0].Data)
	}
}

func TestSubmissionAcceptsAuthLogin(t *testing.T) {
	gw := newTestGateway(t)
	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewLoginClient(testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH LOGIN: %v", err)
	}
}

func TestSubmissionRejectsBadPassword(t *testing.T) {
	gw := newTestGateway(t)
	c := gw.dialSubmission(t)
	err := c.Auth(sasl.NewPlainClient("", testAccount, "wrong"))
	if err == nil {
		t.Fatal("expected AUTH to fail")
	}
	if !strings.Contains(err.Error(), "535") {
		t.Fatalf("want a 535 authentication failure, got %v", err)
	}
}

// Without AUTH, the gateway must refuse to accept mail: it is a submission
// relay, never an open one.
func TestSubmissionRefusesUnauthenticatedMail(t *testing.T) {
	gw := newTestGateway(t)
	c := gw.dialSubmission(t)
	err := c.Mail("app@example.test", nil)
	if err == nil {
		t.Fatal("expected MAIL FROM to be refused")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("want 502 (authentication required), got %v", err)
	}
	if len(gw.upstream.received()) != 0 {
		t.Fatal("upstream received a message from an unauthenticated client")
	}
}

// AUTH must not even be offered before the connection is encrypted.
func TestAuthNotOfferedInClear(t *testing.T) {
	gw := newTestGateway(t)
	c, err := smtp.Dial(gw.submissionAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if err := c.Hello("client.test"); err != nil {
		t.Fatalf("EHLO: %v", err)
	}
	if ok, _ := c.Extension("AUTH"); ok {
		t.Fatal("AUTH advertised on a cleartext connection")
	}
	if ok, _ := c.Extension("STARTTLS"); !ok {
		t.Fatal("STARTTLS not advertised")
	}
}

// The implicit-TLS listener (port 465 in production) must serve the same
// certificates and accept the same credentials.
func TestImplicitTLSListener(t *testing.T) {
	gw := newTestGateway(t)
	c, err := smtp.DialTLS(gw.smtpsAddr, gw.clientTLS())
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer c.Close()
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	if err := c.SendMail("app@example.test", []string{"dest@example.test"},
		strings.NewReader("Subject: implicit\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	if len(gw.upstream.received()) != 1 {
		t.Fatal("message not relayed over implicit TLS")
	}
}

// An upstream rejection must reach the client with the upstream's own status
// code, so that a permanent failure is not retried forever.
func TestUpstreamRejectionIsPropagated(t *testing.T) {
	gw := newTestGateway(t)
	gw.upstream.reject(&smtp.SMTPError{
		Code:         550,
		EnhancedCode: smtp.EnhancedCode{5, 7, 1},
		Message:      "Rejected by policy",
	})
	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	err := c.SendMail("app@example.test", []string{"dest@example.test"},
		strings.NewReader("Subject: nope\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("expected the upstream rejection to be propagated")
	}
	if !strings.Contains(err.Error(), "550") || !strings.Contains(err.Error(), "Rejected by policy") {
		t.Fatalf("want the upstream 550, got %v", err)
	}
}

// The filter chain must be wired into the session, not just unit-tested: a
// message a filter rejects never reaches the upstream.
func TestFilteredMessageIsRejectedBeforeRelaying(t *testing.T) {
	address := startTestMilter(t, &testMilterBackend{rejectOn: eicarPattern})
	gw := newTestGateway(t, func(cfg *Config) {
		cfg.Milters = []Milter{{Name: "scanner", Address: address}}
	})

	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	err := c.SendMail("app@example.test", []string{"dest@example.test"},
		strings.NewReader("Subject: infected\r\n\r\n"+eicarPattern+"\r\n"))
	if err == nil {
		t.Fatal("expected the infected message to be rejected")
	}
	if !strings.Contains(err.Error(), "554") || !strings.Contains(err.Error(), "Malware found") {
		t.Fatalf("want the filter's 554, got %v", err)
	}
	if len(gw.upstream.received()) != 0 {
		t.Fatal("an infected message reached the upstream")
	}
}

// A clean message goes through the same chain and comes out with the filter's
// header added.
func TestFilteredMessageKeepsFilterHeader(t *testing.T) {
	address := startTestMilter(t, &testMilterBackend{addHeader: "clean"})
	gw := newTestGateway(t, func(cfg *Config) {
		cfg.Milters = []Milter{{Name: "scanner", Address: address}}
	})

	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	if err := c.SendMail("app@example.test", []string{"dest@example.test"},
		strings.NewReader("Subject: fine\r\n\r\nhello\r\n")); err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	msgs := gw.upstream.received()
	if len(msgs) != 1 {
		t.Fatalf("upstream got %d messages", len(msgs))
	}
	if !strings.Contains(string(msgs[0].Data), "X-Test-Filter: clean") {
		t.Fatalf("filter header missing:\n%s", msgs[0].Data)
	}
}

// An account may opt out of one of the gateway's filters; the others still run.
func TestAccountCanDisableAFilter(t *testing.T) {
	rejecting := startTestMilter(t, &testMilterBackend{rejectOn: "hello"})
	gw := newTestGateway(t, func(cfg *Config) {
		cfg.Milters = []Milter{{Name: "picky", Address: rejecting}}
		cfg.Accounts[0].DisableMilters = []string{"picky"}
	})

	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	if err := c.SendMail("app@example.test", []string{"dest@example.test"},
		strings.NewReader("Subject: fine\r\n\r\nhello\r\n")); err != nil {
		t.Fatalf("the disabled filter still rejected the message: %v", err)
	}
	if len(gw.upstream.received()) != 1 {
		t.Fatal("message not relayed")
	}
}

// An account's own DKIM key overrides the gateway's.
func TestAccountDKIMOverridesTheGatewayKey(t *testing.T) {
	gatewayKey, _ := dkimTestKey(t, "rsa", "example.test", "gw")
	accountKey, accountLookup := dkimTestKey(t, "rsa", "example.test", "acct")
	gw := newTestGateway(t, func(cfg *Config) {
		cfg.DKIM = []DKIMKey{gatewayKey}
		cfg.Accounts[0].DKIM = []DKIMKey{accountKey}
	})

	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	if err := c.SendMail("app@example.test", []string{"dest@example.test"},
		strings.NewReader("From: app@example.test\r\nSubject: signed\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	msgs := gw.upstream.received()
	if len(msgs) != 1 {
		t.Fatalf("upstream got %d messages", len(msgs))
	}
	// Only the account's selector verifies, which proves its key was used.
	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(msgs[0].Data),
		&dkim.VerifyOptions{LookupTXT: accountLookup})
	if err != nil || len(verifications) != 1 || verifications[0].Err != nil {
		t.Fatalf("account key did not sign the message: %v %+v", err, verifications)
	}
}
