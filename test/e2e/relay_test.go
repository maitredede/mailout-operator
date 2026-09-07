//go:build e2e

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package e2e

import (
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// send authenticates and submits one message, returning the server's verdict.
func (s *stack) send(t *testing.T, subject, from, body string) error {
	t.Helper()
	client, err := smtp.DialStartTLS(s.SubmissionAddr, &tls.Config{
		ServerName: testCertName, RootCAs: s.CAPool, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer client.Close()
	if err := client.Auth(sasl.NewPlainClient("", testUsername, testPassword)); err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	message := fmt.Sprintf("From: %s\r\nTo: dest@elsewhere.test\r\nSubject: %s\r\n\r\n%s\r\n",
		from, subject, body)
	return client.SendMail(from, []string{"dest@elsewhere.test"}, strings.NewReader(message))
}

// The baseline: an authenticated submission reaches the real target server.
func TestRelayToRealServer(t *testing.T) {
	stack := newStack(t, newNetwork(t))

	if err := stack.send(t, "e2e relay", "app@"+testDomain, "hello from the e2e suite"); err != nil {
		t.Fatalf("submission refused: %v", err)
	}
	msg := stack.Mailpit.waitForMessage(t, "e2e relay", 15*time.Second)
	raw := stack.Mailpit.raw(t, msg.ID)
	if !strings.Contains(raw, "hello from the e2e suite") {
		t.Fatalf("body did not survive the relay:\n%s", raw)
	}
	if !strings.Contains(raw, "with ESMTPSA id "+testUsername) {
		t.Fatalf("the gateway's Received header is missing:\n%s", raw)
	}
}

// The signature must verify against the published key, and cover the body that
// actually left the gateway.
func TestRelayedMessageIsSigned(t *testing.T) {
	stack := newStack(t, newNetwork(t))

	if err := stack.send(t, "e2e dkim", "app@"+testDomain, "signed body"); err != nil {
		t.Fatalf("submission refused: %v", err)
	}
	msg := stack.Mailpit.waitForMessage(t, "e2e dkim", 15*time.Second)
	raw := stack.Mailpit.raw(t, msg.ID)

	lookup := func(name string) ([]string, error) {
		want := testSelector + "._domainkey." + testDomain
		if name != want {
			return nil, fmt.Errorf("unexpected lookup for %q", name)
		}
		return []string{stack.DKIMRecord}, nil
	}
	verifications, err := dkim.VerifyWithOptions(strings.NewReader(raw),
		&dkim.VerifyOptions{LookupTXT: lookup})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(verifications) != 1 {
		t.Fatalf("got %d signatures:\n%s", len(verifications), raw)
	}
	if verifications[0].Err != nil {
		t.Fatalf("signature does not verify: %v", verifications[0].Err)
	}
}

// A sender the gateway has no key for goes out unsigned rather than mis-signed.
func TestMessageFromUnknownDomainIsRelayedUnsigned(t *testing.T) {
	stack := newStack(t, newNetwork(t))

	if err := stack.send(t, "e2e unsigned", "app@other.test", "no key for this domain"); err != nil {
		t.Fatalf("submission refused: %v", err)
	}
	msg := stack.Mailpit.waitForMessage(t, "e2e unsigned", 15*time.Second)
	if raw := stack.Mailpit.raw(t, msg.ID); strings.Contains(raw, "DKIM-Signature:") {
		t.Fatalf("a message was signed under a domain with no key:\n%s", raw)
	}
}

func TestWrongPasswordIsRefused(t *testing.T) {
	stack := newStack(t, newNetwork(t))

	client, err := smtp.DialStartTLS(stack.SubmissionAddr, &tls.Config{
		ServerName: testCertName, RootCAs: stack.CAPool, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	err = client.Auth(sasl.NewPlainClient("", testUsername, "not-the-password"))
	if err == nil {
		t.Fatal("a wrong password was accepted")
	}
	if !strings.Contains(err.Error(), "535") {
		t.Fatalf("want a 535, got %v", err)
	}
}

// The implicit-TLS port must serve the same accounts and reach the same target.
func TestImplicitTLSPortRelays(t *testing.T) {
	stack := newStack(t, newNetwork(t))

	client, err := smtp.DialTLS(stack.SMTPSAddr, &tls.Config{
		ServerName: testCertName, RootCAs: stack.CAPool, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if err := client.Auth(sasl.NewPlainClient("", testUsername, testPassword)); err != nil {
		t.Fatalf("auth: %v", err)
	}
	body := "From: app@" + testDomain + "\r\nTo: dest@elsewhere.test\r\nSubject: e2e smtps\r\n\r\nimplicit\r\n"
	if err := client.SendMail("app@"+testDomain, []string{"dest@elsewhere.test"},
		strings.NewReader(body)); err != nil {
		t.Fatalf("submission refused: %v", err)
	}
	stack.Mailpit.waitForMessage(t, "e2e smtps", 15*time.Second)
}

// With a real ClamAV in the chain, an infected message must be refused and a
// clean one must come out carrying the scanner's headers. Slow: the first run
// downloads the signature database.
func TestClamAVScansTheMessage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the ClamAV scenario in -short mode: it downloads the signature database")
	}
	nw := newNetwork(t)
	stack := newStack(t, nw, withClamAV(t, nw))

	err := stack.send(t, "e2e infected", "app@"+testDomain, eicar)
	if err == nil {
		t.Fatal("an EICAR message was accepted")
	}
	if !strings.Contains(err.Error(), "Malware detected") {
		t.Fatalf("the scanner's own reason should reach the client, got %v", err)
	}

	if err := stack.send(t, "e2e clean", "app@"+testDomain, "nothing to see here"); err != nil {
		t.Fatalf("a clean message was refused: %v", err)
	}
	msg := stack.Mailpit.waitForMessage(t, "e2e clean", 30*time.Second)
	raw := stack.Mailpit.raw(t, msg.ID)
	if !strings.Contains(raw, "X-Virus-Scanned:") {
		t.Fatalf("the scanner's header was not applied:\n%s", raw)
	}
	// Signing happens after the filters, so the signature must cover the
	// headers ClamAV added.
	if !strings.Contains(raw, "X-Virus-Status") {
		t.Fatalf("X-Virus-Status missing:\n%s", raw)
	}
	if !strings.Contains(raw, "DKIM-Signature:") {
		t.Fatalf("a scanned message must still be signed:\n%s", raw)
	}
}
