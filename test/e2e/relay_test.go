//go:build e2e

// Copyright (c) 2026 Damien Daly. All rights reserved.

package e2e

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/maitredede/mailout-operator/internal/gateway"
)

// send authenticates as the signing account and submits one message.
func (s *stack) send(t *testing.T, subject, from, body string) error {
	return s.sendAs(t, testUsername, subject, from, body)
}

// sendAs submits as a given account, returning the server's verdict.
func (s *stack) sendAs(t *testing.T, username, subject, from, body string) error {
	t.Helper()
	client, err := smtp.DialStartTLS(s.SubmissionAddr, &tls.Config{
		ServerName: testCertName, RootCAs: s.CAPool, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer client.Close()
	if err := client.Auth(sasl.NewPlainClient("", username, testPassword)); err != nil {
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

// An account that declared its senders may only use them, and the refusal is
// permanent: nothing about retrying changes its configuration.
func TestUndeclaredSenderIsRefused(t *testing.T) {
	stack := newStack(t, newNetwork(t))

	err := stack.send(t, "e2e undeclared", "app@other.test", "not my domain")
	if err == nil {
		t.Fatal("an undeclared sender was accepted")
	}
	if !strings.Contains(err.Error(), "550") {
		t.Fatalf("want a permanent 550, got %v", err)
	}
	if len(stack.Mailpit.messages(t)) != 0 {
		t.Fatal("the refused message reached the upstream")
	}
}

// A domain the gateway holds no key for relays unsigned, rather than being
// signed under a domain that is not the sender's. And a domain granted to
// someone else is refused outright, which is the same account proving both
// halves of the rule.
func TestGrantedDomainWithoutAKeyRelaysUnsigned(t *testing.T) {
	stack := newStack(t, newNetwork(t))

	if err := stack.sendAs(t, openUsername, "not mine", "app@"+testDomain,
		"a domain granted to another account"); err == nil {
		t.Fatal("an account sent from a domain it was not granted")
	}

	const subject = "e2e unsigned"
	if err := stack.sendAs(t, openUsername, subject, "app@"+unsignedDomain, "granted, unsigned"); err != nil {
		t.Fatalf("submission refused: %v", err)
	}
	msg := stack.Mailpit.waitForMessage(t, subject, 15*time.Second)
	if raw := stack.Mailpit.raw(t, msg.ID); strings.Contains(raw, "DKIM-Signature:") {
		t.Fatalf("a domain with no key on the gateway got signed anyway:\n%s", raw)
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

// The quota is enforced against a real Valkey, shared by every replica of the
// gateway — which is the whole reason it is not an in-process counter.
func TestQuotaIsEnforcedAgainstARealStore(t *testing.T) {
	network := newNetwork(t)
	store := startValkey(t, network)
	const quota = 3
	stack := newStack(t, network, func(cfg *gateway.Config) {
		cfg.RateLimit = &gateway.RateLimit{
			Store:             gateway.RateLimitStore{Addresses: []string{store.Address}},
			MessagesPerMinute: quota,
		}
	})

	for i := range quota {
		subject := fmt.Sprintf("quota %d", i)
		if err := stack.sendAs(t, testUsername, subject, "app@"+testDomain, "under the quota"); err != nil {
			t.Fatalf("message %d was refused although it is within the quota: %v", i, err)
		}
	}

	err := stack.sendAs(t, testUsername, "over quota", "app@"+testDomain, "one too many")
	if err == nil {
		t.Fatal("the message over quota was accepted")
	}
	// 452 4.2.2, a temporary refusal: the client is expected to hold the
	// message and try again, not to give up on it.
	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) || smtpErr.Code != 452 {
		t.Fatalf("error = %v, want a 452", err)
	}

	// The other account must be unaffected: the counter is per account, so one
	// tenant exhausting its quota cannot deny service to another.
	if err := stack.sendAs(t, openUsername, "other tenant", "someone@elsewhere.test",
		"a different account"); err != nil {
		t.Fatalf("the other account was refused: %v", err)
	}
}

// Fail-closed, proved by taking the store away rather than by mocking an error:
// the point is that the client actually reports the failure and the relay
// actually refuses.
func TestRelayFailsClosedWhenTheStoreIsGone(t *testing.T) {
	network := newNetwork(t)
	store := startValkey(t, network)
	stack := newStack(t, network, func(cfg *gateway.Config) {
		cfg.RateLimit = &gateway.RateLimit{
			Store: gateway.RateLimitStore{
				Addresses: []string{store.Address},
				// Short, so a missing store refuses quickly instead of hanging
				// the submitting application.
				Timeout: gateway.Duration(2 * time.Second),
			},
			MessagesPerMinute: 100,
		}
	})

	if err := stack.sendAs(t, testUsername, "before", "app@"+testDomain, "store is up"); err != nil {
		t.Fatalf("submission refused while the store is up: %v", err)
	}

	store.stop(t)

	err := stack.sendAs(t, testUsername, "after", "app@"+testDomain, "store is gone")
	if err == nil {
		t.Fatal("the message was relayed although the quota store is gone")
	}
	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) || smtpErr.Code != 451 {
		t.Fatalf("error = %v, want a 451", err)
	}
	// And nothing leaked through: fail-closed means the message did not reach
	// the upstream, not merely that the client saw an error.
	if _, found := stack.Mailpit.find(t, "after"); found {
		t.Fatal("the message reached the upstream although it was refused")
	}
}
