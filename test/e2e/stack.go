//go:build e2e

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

// Package e2e drives the dataplane against the real services it is meant to
// work with: a real SMTP target and a real ClamAV. The gateway itself runs
// in-process, so a failure points at a line of Go rather than at a container.
package e2e

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maitredede/mailout-operator/internal/gateway"
	"github.com/maitredede/mailout-operator/internal/pki"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Images the stack runs. Pinned, so a test failure is never a surprise upgrade.
const (
	mailpitImage = "axllent/mailpit:v1.31.1"
	clamavImage  = "clamav/clamav:1.5.4"
)

// Account credentials the tests authenticate with.
const (
	testUsername = "app1"
	testPassword = "e2e-password"
	testCertName = "mailout.e2e.test"
	testDomain   = "example.test"
	testSelector = "mail"
)

// eicar is the standard antivirus test string. Written in pieces so that this
// source file is not itself flagged by a scanner.
var eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$` + `EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// stack is a running gateway plus what it talks to.
type stack struct {
	// SubmissionAddr is the STARTTLS listener, on the host.
	SubmissionAddr string
	// SMTPSAddr is the implicit-TLS listener, on the host.
	SMTPSAddr string
	// CAPool trusts the gateway's throwaway certificate.
	CAPool *x509.CertPool
	// Mailpit is the SMTP target, and the oracle the assertions read.
	Mailpit *mailpit
	// DKIMRecord is the TXT value that publishes the signing key.
	DKIMRecord string
}

// stackOption adjusts the gateway configuration before it starts.
type stackOption func(*gateway.Config)

// withClamAV starts a real ClamAV and wires it as a milter. It is slow: the
// first run downloads the signature database.
func withClamAV(t *testing.T, net *testcontainers.DockerNetwork) stackOption {
	t.Helper()
	address := startClamAV(t, net)
	return func(cfg *gateway.Config) {
		cfg.Milters = []gateway.Milter{{
			Name:    "clamav",
			Address: "tcp://" + address,
			Timeout: gateway.Duration(60 * time.Second),
		}}
	}
}

// newStack starts the target server and the gateway.
func newStack(t *testing.T, network *testcontainers.DockerNetwork, opts ...stackOption) *stack {
	t.Helper()

	mp := startMailpit(t, network)

	ca, err := pki.NewCA("mailout e2e")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	serverCert, err := ca.Issue(testCertName, "localhost", "127.0.0.1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)

	dkimKey, err := gateway.GenerateDKIMKey("rsa", testDomain, testSelector)
	if err != nil {
		t.Fatalf("GenerateDKIMKey: %v", err)
	}
	hash, err := gateway.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	cfg := &gateway.Config{
		Hostname: testCertName,
		Listeners: []gateway.Listener{
			{Name: "submission", Addr: "127.0.0.1:0", Mode: gateway.TLSModeSTARTTLS},
			{Name: "smtps", Addr: "127.0.0.1:0", Mode: gateway.TLSModeImplicit},
		},
		TLS: gateway.TLSConfig{Certificates: []gateway.CertificateRef{{
			Name:    "gateway",
			CertPEM: string(serverCert.CertPEM),
			KeyPEM:  string(serverCert.KeyPEM),
		}}},
		Upstream: gateway.Upstream{Host: mp.SMTPHost, Port: mp.SMTPPort, TLS: gateway.TLSModeNone},
		Accounts: []gateway.Account{{Username: testUsername, PasswordHash: hash}},
		DKIM: []gateway.DKIMKey{{
			Domain:        testDomain,
			Selector:      testSelector,
			PrivateKeyPEM: dkimKey.PrivateKeyPEM,
		}},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	srv, err := gateway.NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	addrs := make(chan string, 2)
	srv.SetOnListen(func(_ gateway.Listener, addr string) { addrs <- addr })

	done := make(chan error, 1)
	go func() { done <- srv.Run(t.Context()) }()
	t.Cleanup(func() {
		srv.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("the gateway did not stop")
		}
	})

	s := &stack{CAPool: pool, Mailpit: mp, DKIMRecord: dkimKey.DNSRecordValue}
	for range 2 {
		select {
		case addr := <-addrs:
			if s.SubmissionAddr == "" {
				s.SubmissionAddr = addr
			} else {
				s.SMTPSAddr = addr
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the gateway did not start listening")
		}
	}
	return s
}

// newNetwork creates a docker network the containers share, so clamav-milter
// can reach clamd by name.
func newNetwork(t *testing.T) *testcontainers.DockerNetwork {
	t.Helper()
	// The network outlives t.Context(), which is cancelled before Cleanup runs.
	nw, err := tcnetwork.New(context.Background())
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	t.Cleanup(func() {
		if err := nw.Remove(context.Background()); err != nil {
			t.Logf("remove network: %v", err)
		}
	})
	return nw
}

// mailpit is the SMTP target and its HTTP API.
type mailpit struct {
	SMTPHost string
	SMTPPort int
	APIURL   string
}

func startMailpit(t *testing.T, nw *testcontainers.DockerNetwork) *mailpit {
	t.Helper()
	// Containers are stopped from Cleanup, which runs after t.Context() is
	// already cancelled — hence the background context here and below.
	ctx := context.Background()

	container, err := testcontainers.Run(ctx, mailpitImage,
		testcontainers.WithExposedPorts("1025/tcp", "8025/tcp"),
		testcontainers.WithEnv(map[string]string{
			"MP_SMTP_AUTH_ACCEPT_ANY":     "true",
			"MP_SMTP_AUTH_ALLOW_INSECURE": "true",
		}),
		tcnetwork.WithNetwork([]string{"mailpit"}, nw),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("1025/tcp")),
	)
	if err != nil {
		t.Fatalf("start mailpit: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("mailpit host: %v", err)
	}
	smtpPort, err := container.MappedPort(ctx, "1025/tcp")
	if err != nil {
		t.Fatalf("mailpit smtp port: %v", err)
	}
	apiPort, err := container.MappedPort(ctx, "8025/tcp")
	if err != nil {
		t.Fatalf("mailpit api port: %v", err)
	}
	port, err := strconv.Atoi(smtpPort.Port())
	if err != nil {
		t.Fatalf("mailpit smtp port %q: %v", smtpPort.Port(), err)
	}
	return &mailpit{
		SMTPHost: host,
		SMTPPort: port,
		APIURL:   fmt.Sprintf("http://%s:%s", host, apiPort.Port()),
	}
}

// startClamAV runs clamd and clamav-milter, and returns the milter's host
// address.
func startClamAV(t *testing.T, nw *testcontainers.DockerNetwork) string {
	t.Helper()
	ctx := context.Background()

	clamd, err := testcontainers.Run(ctx, clamavImage,
		testcontainers.WithEnv(map[string]string{"CLAMAV_NO_MILTERD": "true"}),
		tcnetwork.WithNetwork([]string{"clamav"}, nw),
		// The first start downloads the signature database, which is why this
		// deadline is minutes rather than seconds.
		testcontainers.WithWaitStrategyAndDeadline(6*time.Minute,
			wait.ForLog("socket found, clamd started")),
	)
	if err != nil {
		t.Fatalf("start clamd: %v", err)
	}
	t.Cleanup(func() { _ = clamd.Terminate(ctx) })

	const milterConf = `MilterSocket inet:7357
Foreground yes
ClamdSocket tcp:clamav:3310
OnInfected Reject
RejectMsg "Malware detected: %v"
AddHeader Replace
LogSyslog no
LogInfected Basic
User clamav
FixStaleSocket yes
`
	milter, err := testcontainers.Run(ctx, clamavImage,
		testcontainers.WithEntrypoint("clamav-milter", "--config-file=/etc/clamav/milter.conf"),
		testcontainers.WithFiles(testcontainers.ContainerFile{
			Reader:            strings.NewReader(milterConf),
			ContainerFilePath: "/etc/clamav/milter.conf",
			FileMode:          0o644,
		}),
		testcontainers.WithExposedPorts("7357/tcp"),
		tcnetwork.WithNetwork([]string{"clamav-milter"}, nw),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("7357/tcp")),
	)
	if err != nil {
		t.Fatalf("start clamav-milter: %v", err)
	}
	t.Cleanup(func() { _ = milter.Terminate(ctx) })

	host, err := milter.Host(ctx)
	if err != nil {
		t.Fatalf("milter host: %v", err)
	}
	port, err := milter.MappedPort(ctx, "7357/tcp")
	if err != nil {
		t.Fatalf("milter port: %v", err)
	}
	return net.JoinHostPort(host, port.Port())
}

// message is one message as Mailpit reports it.
type message struct {
	ID      string
	Subject string
}

// messages lists what the target server received.
func (m *mailpit) messages(t *testing.T) []message {
	t.Helper()
	var payload struct {
		Total    int
		Messages []message
	}
	m.getJSON(t, "/api/v1/messages", &payload)
	return payload.Messages
}

// raw returns a received message as it arrived on the wire, which is what the
// DKIM assertions need.
func (m *mailpit) raw(t *testing.T, id string) string {
	t.Helper()
	resp, err := http.Get(m.APIURL + "/api/v1/message/" + id + "/raw")
	if err != nil {
		t.Fatalf("fetch raw message: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read raw message: %v", err)
	}
	return string(body)
}

// waitForMessage polls until a message with the given subject arrives.
func (m *mailpit) waitForMessage(t *testing.T, subject string, timeout time.Duration) message {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, msg := range m.messages(t) {
			if msg.Subject == subject {
				return msg
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no message with subject %q arrived within %s", subject, timeout)
	return message{}
}

func (m *mailpit) getJSON(t *testing.T, path string, out any) {
	t.Helper()
	resp, err := http.Get(m.APIURL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}
