// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/d--j/go-milter"
)

// eicarPattern stands in for a virus signature. The real EICAR string is used
// against ClamAV in the end-to-end tests; here a marker is enough to exercise
// the protocol.
const eicarPattern = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"

// testMilter is a filter written with the server side of go-milter, so the
// chain is exercised over a real milter conversation without any container.
type testMilter struct {
	milter.NoOpMilter
	backend *testMilterBackend
	body    strings.Builder
	from    string
}

type testMilterBackend struct {
	// rejectOn, when non-empty, rejects any message whose body contains it.
	rejectOn string
	// addHeader, when non-empty, is added to every accepted message.
	addHeader string
	// replaceBody, when non-empty, replaces the body.
	replaceBody string
	// discard makes the filter ask for a silent drop.
	discard bool
	// quarantine makes the filter ask for quarantine.
	quarantine bool

	mu sync.Mutex
	// seenMacros records what the gateway told us about the session.
	seenAuthUser string
	seenTLS      string
}

func (b *testMilterBackend) observed() (authUser, tlsVersion string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seenAuthUser, b.seenTLS
}

func (m *testMilter) MailFrom(from, _ string, mod milter.Modifier) (*milter.Response, error) {
	m.from = from
	m.backend.mu.Lock()
	m.backend.seenAuthUser = mod.Get(milter.MacroAuthAuthen)
	m.backend.seenTLS = mod.Get(milter.MacroTlsVersion)
	m.backend.mu.Unlock()
	return milter.RespContinue, nil
}

func (m *testMilter) BodyChunk(chunk []byte, _ milter.Modifier) (*milter.Response, error) {
	m.body.Write(chunk)
	return milter.RespContinue, nil
}

func (m *testMilter) EndOfMessage(mod milter.Modifier) (*milter.Response, error) {
	b := m.backend
	if b.rejectOn != "" && strings.Contains(m.body.String(), b.rejectOn) {
		return milter.RejectWithCodeAndReason(554, "5.7.1 Malware found: Test.Signature")
	}
	if b.discard {
		return milter.RespDiscard, nil
	}
	if b.quarantine {
		if err := mod.Quarantine("suspicious"); err != nil {
			return nil, err
		}
		return milter.RespAccept, nil
	}
	if b.addHeader != "" {
		if err := mod.AddHeader("X-Test-Filter", b.addHeader); err != nil {
			return nil, err
		}
	}
	if b.replaceBody != "" {
		if err := mod.ReplaceBody(strings.NewReader(b.replaceBody)); err != nil {
			return nil, err
		}
	}
	return milter.RespAccept, nil
}

// startTestMilter runs the filter and returns its address.
func startTestMilter(t *testing.T, backend *testMilterBackend) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := milter.NewServer(
		milter.WithMilter(func() milter.Milter { return &testMilter{backend: backend} }),
		milter.WithAction(milter.OptAddHeader|milter.OptChangeHeader|milter.OptChangeBody|
			milter.OptAddRcpt|milter.OptRemoveRcpt|milter.OptChangeFrom|milter.OptQuarantine),
		milter.WithMacroRequest(milter.StageMail, []milter.MacroName{
			milter.MacroAuthAuthen, milter.MacroTlsVersion,
		}),
	)
	go func() { _ = srv.Serve(l) }()
	// The server owns the listener; Close stops it. Registered as Cleanup, which
	// runs after t.Context() is already cancelled — hence no context here.
	t.Cleanup(func() { _ = srv.Close() })
	return "tcp://" + l.Addr().String()
}

// testLogger writes to stderr under `go test -v`, and discards otherwise: a
// filter failure is otherwise invisible, since the chain reports it as a plain
// 451 to the client.
func testLogger() *slog.Logger {
	if testing.Verbose() {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.DiscardHandler)
}

func newTestChain(t *testing.T, filters ...Milter) *milterChain {
	t.Helper()
	chain, err := newMilterChain(&Config{Milters: filters}, testLogger())
	if err != nil {
		t.Fatalf("newMilterChain: %v", err)
	}
	return chain
}

func testMessage() *Message {
	return &Message{
		From:    "app@example.test",
		To:      []string{"dest@example.test"},
		Account: "app1",
		Data:    []byte("From: app@example.test\r\nSubject: hi\r\n\r\nclean body\r\n"),
	}
}

func testSessionInfo() sessionInfo {
	return sessionInfo{
		Hostname:   "client.test",
		RemoteIP:   "127.0.0.1",
		RemotePort: 1234,
		TLSVersion: "TLS 1.3",
		TLSCipher:  "TLS_AES_128_GCM_SHA256",
		AuthUser:   "app1",
		MTAName:    "gateway.test",
	}
}

func TestMilterChainAddsHeaderAndPassesSessionInfo(t *testing.T) {
	backend := &testMilterBackend{addHeader: "scanned"}
	chain := newTestChain(t, Milter{Name: "test", Address: startTestMilter(t, backend)})

	msg := testMessage()
	if err := chain.run(t.Context(), msg, testSessionInfo()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(string(msg.Data), "X-Test-Filter: scanned") {
		t.Fatalf("header not applied:\n%s", msg.Data)
	}
	if !strings.Contains(string(msg.Data), "clean body") {
		t.Fatalf("body altered:\n%s", msg.Data)
	}
	authUser, tlsVersion := backend.observed()
	if authUser != "app1" {
		t.Fatalf("filter saw auth user %q, want app1", authUser)
	}
	if tlsVersion != "TLS 1.3" {
		t.Fatalf("filter saw TLS version %q", tlsVersion)
	}
}

func TestMilterChainRejectionCarriesTheFiltersCode(t *testing.T) {
	chain := newTestChain(t, Milter{
		Name:    "scanner",
		Address: startTestMilter(t, &testMilterBackend{rejectOn: eicarPattern}),
	})

	msg := testMessage()
	msg.Data = []byte("Subject: infected\r\n\r\n" + eicarPattern + "\r\n")
	err := chain.run(t.Context(), msg, testSessionInfo())
	if err == nil {
		t.Fatal("expected the message to be rejected")
	}
	if !strings.Contains(err.Error(), "554") || !strings.Contains(err.Error(), "Malware found") {
		t.Fatalf("want the filter's 554, got %v", err)
	}
}

func TestMilterChainReplacesBody(t *testing.T) {
	chain := newTestChain(t, Milter{
		Name:    "rewriter",
		Address: startTestMilter(t, &testMilterBackend{replaceBody: "sanitized\r\n"}),
	})
	msg := testMessage()
	if err := chain.run(t.Context(), msg, testSessionInfo()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(string(msg.Data), "clean body") {
		t.Fatalf("body not replaced:\n%s", msg.Data)
	}
	if !strings.Contains(string(msg.Data), "sanitized") {
		t.Fatalf("replacement missing:\n%s", msg.Data)
	}
	if !strings.Contains(string(msg.Data), "Subject: hi") {
		t.Fatalf("headers lost:\n%s", msg.Data)
	}
}

func TestMilterChainDiscard(t *testing.T) {
	chain := newTestChain(t, Milter{
		Name:    "dropper",
		Address: startTestMilter(t, &testMilterBackend{discard: true}),
	})
	err := chain.run(t.Context(), testMessage(), testSessionInfo())
	if !errors.Is(err, errDiscard) {
		t.Fatalf("want errDiscard, got %v", err)
	}
}

// Quarantine has nowhere to go without a spool, so it must become a visible
// rejection rather than a silent drop.
func TestMilterChainQuarantineBecomesRejection(t *testing.T) {
	chain := newTestChain(t, Milter{
		Name:    "quarantiner",
		Address: startTestMilter(t, &testMilterBackend{quarantine: true}),
	})
	err := chain.run(t.Context(), testMessage(), testSessionInfo())
	if err == nil || !strings.Contains(err.Error(), "554") {
		t.Fatalf("want a 554 rejection, got %v", err)
	}
}

// An unreachable filter must stop the message by default: a scanner that is
// down must not silently turn the relay into a malware conduit.
func TestMilterChainFailClosed(t *testing.T) {
	chain := newTestChain(t, Milter{Name: "down", Address: "tcp://127.0.0.1:1"})
	err := chain.run(t.Context(), testMessage(), testSessionInfo())
	if err == nil {
		t.Fatal("expected an unreachable filter to reject the message")
	}
	if !strings.Contains(err.Error(), "451") {
		t.Fatalf("want a temporary 451, got %v", err)
	}
}

func TestMilterChainFailOpen(t *testing.T) {
	chain := newTestChain(t, Milter{Name: "down", Address: "tcp://127.0.0.1:1", FailOpen: true})
	if err := chain.run(t.Context(), testMessage(), testSessionInfo()); err != nil {
		t.Fatalf("failOpen should let the message through, got %v", err)
	}
}

// Filters run in order, and each one sees what the previous left behind.
func TestMilterChainRunsFiltersInOrder(t *testing.T) {
	first := startTestMilter(t, &testMilterBackend{addHeader: "first"})
	second := startTestMilter(t, &testMilterBackend{rejectOn: "X-Test-Filter"})
	chain := newTestChain(t,
		Milter{Name: "first", Address: first},
		Milter{Name: "second", Address: second},
	)
	// The second filter only inspects the body, so it must not see the header
	// the first one added — this pins that headers and body stay separate.
	msg := testMessage()
	if err := chain.run(t.Context(), msg, testSessionInfo()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(string(msg.Data), "X-Test-Filter: first") {
		t.Fatalf("first filter's header missing:\n%s", msg.Data)
	}
}

func TestMilterAddressParsing(t *testing.T) {
	tests := []struct {
		address     string
		wantNetwork string
		wantAddr    string
		wantErr     bool
	}{
		{"tcp://127.0.0.1:7357", "tcp", "127.0.0.1:7357", false},
		{"unix:///run/clamav/milter.sock", "unix", "/run/clamav/milter.sock", false},
		{"clamav-milter:7357", "tcp", "clamav-milter:7357", false},
		{"http://nope", "", "", true},
		{"", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.address, func(t *testing.T) {
			network, addr, err := Milter{Address: tc.address}.ParseAddress()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if err == nil && (network != tc.wantNetwork || addr != tc.wantAddr) {
				t.Fatalf("got (%q, %q), want (%q, %q)", network, addr, tc.wantNetwork, tc.wantAddr)
			}
		})
	}
}
