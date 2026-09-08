// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"strings"
	"testing"

	"github.com/emersion/go-sasl"
)

// injectingUsername is the exploit: the trailing blank line ends the header
// block, so everything after it becomes the body of every message the account
// sends. Before usernames were validated, this reached the Received header of
// the relayed message verbatim.
const injectingUsername = "app1\r\nX-Injected: pwned\r\nFrom: ceo@victim.test\r\n\r\nINJECTED BODY"

func TestValidUsername(t *testing.T) {
	for name, tc := range map[string]struct {
		username string
		want     bool
	}{
		"plain":              {"app1", true},
		"namespace default":  {"billing.invoicing", true},
		"address shaped":     {"app@example.com", true},
		"underscore and dot": {"team_a.app-1", true},
		"single character":   {"a", true},
		"empty":              {"", false},
		"carriage return":    {"app\rX: y", false},
		"line feed":          {"app\nX: y", false},
		"the exploit":        {injectingUsername, false},
		"nul":                {"app\x00", false},
		"space":              {"app 1", false},
		"tab":                {"app\t1", false},
		// A colon would let one username be read as another inside a rate
		// limiting key, and inside the Received header's own syntax.
		"colon":        {"app:1", false},
		"semicolon":    {"app;1", false},
		"quote":        {`app"1`, false},
		"backslash":    {`app\1`, false},
		"delete":       {"app\x7f", false},
		"too long":     {strings.Repeat("a", MaxUsernameLength+1), false},
		"at the limit": {strings.Repeat("a", MaxUsernameLength), true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := ValidUsername(tc.username); got != tc.want {
				t.Errorf("ValidUsername(%q) = %v, want %v", tc.username, got, tc.want)
			}
		})
	}
}

// An account whose username could inject must not be served at all: it is the
// one value that reaches a header of every message it sends.
func TestPartitionAccountsRejectsAnInjectingUsername(t *testing.T) {
	hash := mustHash(t, "pw")
	cfg := &Config{Accounts: []Account{
		{Username: "good", PasswordHash: hash},
		{Username: injectingUsername, PasswordHash: hash},
	}}
	served, rejected := cfg.PartitionAccounts()

	if len(served) != 1 || served[0].Username != "good" {
		t.Fatalf("served = %+v, want only the good account", served)
	}
	if len(rejected) != 1 {
		t.Fatalf("rejected = %+v, want one", rejected)
	}
	// The reason travels to a Kubernetes status and to the logs, so it must not
	// carry the control characters it is complaining about.
	if strings.ContainsAny(rejected[0].Username+rejected[0].Reason, "\r\n\x00") {
		t.Errorf("the rejection echoes control characters back: %+v", rejected[0])
	}
}

// The gateway must come up serving everyone else, and the account that tried
// must not be able to authenticate at all.
func TestInjectingAccountCannotAuthenticate(t *testing.T) {
	gw := newTestGateway(t, func(cfg *Config) {
		cfg.Accounts = append(cfg.Accounts, Account{
			Username:     injectingUsername,
			PasswordHash: mustHash(t, testPassword),
		})
	})

	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", injectingUsername, testPassword)); err == nil {
		t.Fatal("an account with an injecting username authenticated")
	}
	_ = c.Close()

	// The legitimate account is unaffected: one tenant's mistake stays its own.
	c = gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("the valid account should still authenticate: %v", err)
	}
}

// headerSafe is the second barrier, and the one that covers values no account
// validation reaches: the EHLO name is chosen by whoever connects.
func TestHeaderSafeNeutralizesEveryInterpolatedValue(t *testing.T) {
	for name, value := range map[string]string{
		"the exploit":    injectingUsername,
		"bare line feed": "host\nX-Injected: pwned",
		"nul":            "host\x00",
		"delete":         "host\x7f",
	} {
		t.Run(name, func(t *testing.T) {
			got := headerSafe(value)
			if strings.ContainsAny(got, "\r\n\x00\x7f") {
				t.Errorf("headerSafe(%q) = %q, still carries a control character", value, got)
			}
			if len(got) > headerSafeLimit {
				t.Errorf("headerSafe returned %d bytes, want at most %d", len(got), headerSafeLimit)
			}
		})
	}
	if got := headerSafe(strings.Repeat("a", headerSafeLimit*2)); len(got) != headerSafeLimit {
		t.Errorf("a long value was not truncated: %d bytes", len(got))
	}
}
