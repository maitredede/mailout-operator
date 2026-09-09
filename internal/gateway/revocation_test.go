// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"strings"
	"testing"

	"github.com/emersion/go-sasl"
)

// A session captured its snapshot when it connected, so a credential stayed
// valid for the life of the connection: deleting the account, disabling it or
// rotating the password changed nothing for a session already open. And nothing
// closes an idle one — a NOOP every 50 seconds keeps it under the read deadline
// forever — so a leaked credential could keep sending after being revoked.
func TestRevokedAccountCannotKeepSending(t *testing.T) {
	gw := newTestGateway(t)

	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	// It works before the revocation, so the test proves a change of state and
	// not merely that something is broken.
	if err := c.Mail("app@example.test", nil); err != nil {
		t.Fatalf("MAIL FROM before revocation: %v", err)
	}
	if err := c.Reset(); err != nil {
		t.Fatalf("RSET: %v", err)
	}

	// The account is removed from the served configuration, as deleting the
	// MailoutAccount would do.
	cfg := *gw.srv.current.Load().config
	cfg.Accounts = nil
	if err := gw.srv.Reload(&cfg); err != nil {
		t.Fatalf("reload without the account: %v", err)
	}

	if err := c.Mail("app@example.test", nil); err == nil {
		t.Error("a deleted account still started a transaction on its open session")
	}
}

// Disabling is the softer revocation and must behave the same way.
func TestDisabledAccountCannotKeepSending(t *testing.T) {
	gw := newTestGateway(t)

	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	if err := c.Mail("app@example.test", nil); err != nil {
		t.Fatalf("MAIL FROM before disabling: %v", err)
	}
	if err := c.Reset(); err != nil {
		t.Fatalf("RSET: %v", err)
	}

	cfg := *gw.srv.current.Load().config
	cfg.Accounts = append([]Account(nil), cfg.Accounts...)
	cfg.Accounts[0].Disabled = true
	if err := gw.srv.Reload(&cfg); err != nil {
		t.Fatalf("reload with the account disabled: %v", err)
	}

	if err := c.Mail("app@example.test", nil); err == nil {
		t.Error("a disabled account still started a transaction on its open session")
	}
}

// A policy narrowed while a session is open applies to that session too: the
// snapshot is adopted, not just checked.
func TestNarrowedSenderPolicyAppliesToAnOpenSession(t *testing.T) {
	gw := newTestGateway(t)

	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	if err := c.Mail("app@example.test", nil); err != nil {
		t.Fatalf("MAIL FROM within the granted policy: %v", err)
	}
	if err := c.Reset(); err != nil {
		t.Fatalf("RSET: %v", err)
	}

	cfg := *gw.srv.current.Load().config
	cfg.Accounts = append([]Account(nil), cfg.Accounts...)
	cfg.Accounts[0].AllowedSenders = []string{"noreply@example.test"}
	if err := gw.srv.Reload(&cfg); err != nil {
		t.Fatalf("reload with a narrower policy: %v", err)
	}

	// Allowed before the reload by *@example.test, refused after it.
	err := c.Mail("app@example.test", nil)
	if err == nil {
		t.Fatal("the open session kept the policy it connected with")
	}
	if !strings.Contains(err.Error(), "550") {
		t.Errorf("want a 550 for a refused sender, got %v", err)
	}
}
