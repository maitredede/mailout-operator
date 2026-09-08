// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"golang.org/x/crypto/bcrypt"
)

func TestUsableHash(t *testing.T) {
	real, err := bcrypt.GenerateFromPassword([]byte("pw"), BcryptCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	cheap, err := bcrypt.GenerateFromPassword([]byte("pw"), MinBcryptCost-1)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	for name, tc := range map[string]struct {
		hash string
		want bool
	}{
		"the real cost": {string(real), true},
		"empty":         {"", false},
		"garbage":       {"not-a-hash", false},
		// Never generated: the cost is a number in the hash, so this is what a
		// tenant writes by hand to stall the relay.
		"cost 31":        {"$2a$31$" + strings.Repeat("a", 53), false},
		"below the band": {string(cheap), false},
		// A cost that is plausible but outside the band is still refused: the
		// point is that only costs this gateway would itself produce are served.
		"cost 20": {"$2a$20$" + strings.Repeat("a", 53), false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := UsableHash(tc.hash); got != tc.want {
				t.Errorf("UsableHash(%.20q) = %v, want %v", tc.hash, got, tc.want)
			}
		})
	}
}

// An account whose hash would stall the relay must not be served — the hash
// comes from a Secret in the tenant's own namespace.
func TestPartitionAccountsRejectsAWeaponisedHash(t *testing.T) {
	cfg := &Config{Accounts: []Account{
		{Username: "good", PasswordHash: mustHash(t, "pw")},
		{Username: "costly", PasswordHash: "$2a$31$" + strings.Repeat("a", 53)},
		{Username: "garbage", PasswordHash: "not-a-hash"},
	}}
	served, rejected := cfg.PartitionAccounts()

	if len(served) != 1 || served[0].Username != "good" {
		t.Fatalf("served = %+v, want only the good account", served)
	}
	if len(rejected) != 2 {
		t.Fatalf("rejected = %+v, want two", rejected)
	}
}

// go-smtp does not count a refused AUTH as a protocol error, so its own error
// threshold never fires: without a counter of our own, one connection can ask
// for password verifications forever, at ~180ms of CPU each.
func TestConnectionIsClosedAfterTooManyAuthFailures(t *testing.T) {
	gw := newTestGateway(t)
	c := gw.dialSubmission(t)

	for i := range maxAuthFailures {
		if err := c.Auth(sasl.NewPlainClient("", testAccount, "wrong")); err == nil {
			t.Fatalf("attempt %d should have failed", i+1)
		}
	}

	// The next attempt is refused without verifying anything, and the
	// connection is closed rather than left available for more.
	start := time.Now()
	err := c.Auth(sasl.NewPlainClient("", testAccount, "wrong"))
	if err == nil {
		t.Fatal("the attempt past the limit should have failed")
	}
	// A real verification is ~180ms at cost 12; a refusal that skipped it is
	// orders of magnitude faster. This is what proves the CPU is not spent.
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("the refusal took %v, so a password was still verified", elapsed)
	}
	if err := c.Noop(); err == nil {
		t.Error("the connection is still usable after too many failures")
	}
}

// The bound belongs to the process: a reload must not widen it.
func TestVerificationSemaphoreSurvivesAReload(t *testing.T) {
	gw := newTestGateway(t)
	before := gw.srv.verifying
	if err := gw.srv.Reload(gw.srv.current.Load().config); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if gw.srv.verifying != before {
		t.Error("the reload replaced the verification semaphore, so a reload widens the bound")
	}
}
